"""HTTP helpers that admit and trace every redirect hop before transport."""

from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from src.core.redactor import register_secret
from src.core.scope_config import extract_host
from src.core.scope_guard import ScopeBlocked, require_action


def _admit(url, tool, method="http_get", redirect=False, source_probe=False):
    parsed = urlsplit(url)
    host = extract_host(url)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    require_action("http_redirect" if redirect else "http", url, host,
                   tool=tool, method=method, port=port, path=parsed.path or "/",
                   source_probe=source_probe)


def guarded_request(call, url, *, tool="http", source_probe=False, **kwargs):
    """requests GET/POST callable; automatic transport redirects are disabled."""
    follow = kwargs.pop("allow_redirects", True)
    method = "http_post" if getattr(call, "__name__", "get") == "post" else "http_get"
    params = kwargs.get("params")
    full_url = url + (("&" if "?" in url else "?") + urlencode(params, doseq=True) if params else "")
    # Register session and per-request keys even if future errors omit their names.
    headers = dict(getattr(getattr(call, "__self__", None), "headers", {}) or {})
    headers.update(kwargs.get("headers") or {})
    for key, value in headers.items():
        if any(word in key.lower() for word in ("key", "authorization", "token", "cookie")):
            register_secret(value)
    history = []
    for hop in range(11):
        _admit(full_url if hop == 0 else url, tool, method, redirect=hop > 0,
               source_probe=source_probe and hop == 0)
        response = call(url, allow_redirects=False, **kwargs)
        status = response.status_code
        if not follow or status not in (301, 302, 303, 307, 308):
            if history:
                response.history = history
            return response
        location = response.headers.get("Location")
        if not isinstance(location, str) or not location:
            return response
        next_url = urljoin(url, location)
        # Never forward custom API credentials to another redirect origin.
        if urlsplit(next_url).netloc.lower() != urlsplit(url).netloc.lower() and any(
                word in key.lower() for key in headers for word in ("key", "authorization", "token", "cookie")):
            from src.core.action_tracer import trace
            trace("http_redirect", next_url, extract_host(next_url), tool=tool,
                  scope_decision="blocked", block_reason="cross_origin_credentials")
            response.close()
            raise ScopeBlocked("cross_origin_credentials")
        history.append(response)
        response.close()
        kwargs.pop("params", None)
        if status == 303 or (status in (301, 302) and method == "http_post"):
            # Current clients use GET; a future POST needs an explicit GET callable.
            if method == "http_post":
                raise ScopeBlocked("post_redirect_requires_get")
        url = next_url
    raise ScopeBlocked("redirect_limit")


class _ScopeRedirectHandler(HTTPRedirectHandler):
    def __init__(self, tool):
        self.tool = tool

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib otherwise follows redirects invisibly inside urlopen().
        _admit(urljoin(req.full_url, newurl), self.tool, redirect=True)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        # urllib does not strip arbitrary API headers on cross-origin redirects.
        if redirected and urlsplit(req.full_url).netloc.lower() != urlsplit(newurl).netloc.lower():
            for key in list(redirected.headers):
                if any(word in key.lower() for word in ("key", "authorization", "token", "cookie")):
                    del redirected.headers[key]
        return redirected


def guarded_urlopen(request, *, timeout, tool="http"):
    url = request.full_url if isinstance(request, Request) else request
    _admit(url, tool)
    return build_opener(_ScopeRedirectHandler(tool)).open(request, timeout=timeout)
