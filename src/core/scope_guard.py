"""Check, rate-limit and trace every application-level outward action."""

import threading
import time
from contextvars import ContextVar

from src.core.action_tracer import trace
from src.core.scope_config import ScopeConfig

_scope: ScopeConfig | None = None
_baseline = ScopeConfig()
_source_ip = ""
_LOCK = threading.RLock()
_next_action = 0.0
_policy_context = ContextVar("dfa_scope", default=None)
_source_context = ContextVar("dfa_source_ip", default=None)


class ScopeBlocked(OSError):
    """A skipped action, compatible with existing network-error handlers."""


def set_scope(config: ScopeConfig | None):
    global _scope, _baseline, _next_action
    with _LOCK:
        if config is None:
            _baseline = ScopeConfig()  # Reload the basis even without engagement rules.
        _scope = config
        # Copies of one scan context share a limiter; later scans get a new one.
        _policy_context.set((config, {"next_action": 0.0}))
        _next_action = 0.0


def set_source_ip(value: str):
    global _source_ip
    _source_ip = value if value != "Unknown" else ""
    _source_context.set(_source_ip)


def _decision(config, target, method, source_ip, port, path, source_probe):
    # Hard exclusions are checked first, independently of all engagement rules.
    allowed, reason = config.is_target_allowed(target, port=port, path=path)
    if not allowed:
        return allowed, reason
    if not config.is_within_timewindow():
        return False, "outside_timewindow"
    if method:
        allowed, reason = config.is_method_allowed(method)
        if not allowed:
            return allowed, reason
    # The fixed egress discovery request is needed before its source is known.
    if not source_probe:
        return config.is_source_allowed(source_ip)
    return True, "source_discovery"


def check_and_trace(action_type: str, command: str, target: str,
                    source_ip: str = "", tool: str = "", method: str = "",
                    port: int | None = None, path: str = "", source_probe: bool = False) -> bool:
    """False skips the action; every decision is appended before execution."""
    global _next_action
    known_source = _source_context.get()
    source_ip = source_ip or (_source_ip if known_source is None else known_source)
    # Only the fixed public-IP bootstrap can precede known source attribution.
    source_probe = (source_probe and action_type == "http" and tool == "external_ip"
                    and method == "http_get" and target in {
                        "api.ipify.org", "checkip.amazonaws.com", "ipinfo.io"})
    with _LOCK:
        policy = _policy_context.get()
        active_scope = _scope if policy is None else policy[0]
        limiter = policy[1] if policy is not None else None
        config = active_scope or _baseline
        allowed, reason = _decision(config, target, method, source_ip, port, path, source_probe)
        if allowed and active_scope is not None:
            # Serialize admission across threads, then recheck time after waiting.
            next_action = limiter["next_action"] if limiter is not None else _next_action
            delay = max(0.0, next_action - time.monotonic())
            if delay:
                time.sleep(delay)
            allowed, reason = _decision(config, target, method, source_ip, port, path, source_probe)
            if allowed:
                _next_action = time.monotonic() + 1.0 / config.rate_limit
                if limiter is not None:
                    limiter["next_action"] = _next_action
        trace(action_type, command, target, source_ip, tool,
              scope_decision=("allowed" if active_scope is not None else "no_scope_loaded") if allowed else "blocked",
              block_reason="" if allowed else reason)
        return allowed


def require_action(*args, **kwargs):
    """Skip through existing error paths without ever calling the transport."""
    if not check_and_trace(*args, **kwargs):
        raise ScopeBlocked("blocked_by_scope")
