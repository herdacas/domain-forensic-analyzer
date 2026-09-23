# Contributing

## Development setup

```bash
git clone https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .[dev]            # pytest, pytest-cov, pylint
```

No API keys are required to run the test suite or the tool itself — active probes and free APIs cover the default path.

## Running checks locally

```bash
pytest tests/ -v --cov=src --cov-report=term-missing   # test suite + coverage
pylint src/                                             # code quality (CI gate: ≥ 8.0)
```

Both run in CI on every push and pull request (`.github/workflows/test.yml`), matrixed across Python 3.10–3.12 on Ubuntu and Windows. A PR won't merge cleanly unless both pass.

## Branch naming

| Prefix | Use for |
|---|---|
| `feature/*` | New functionality, new modules |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation-only changes |
| `chore/*` | Tooling, dependencies, CI config, cleanup |
| `refactor/*` | Internal restructuring with no behavior change |

## Pull request process

1. Branch off `main`.
2. Keep commits scoped — one logical change per commit, descriptive messages (see existing history for the house style: `type(scope): summary`, e.g. `fix(dns): handle empty MX record set`).
3. Add or update tests for anything behavioral. New analyzer fields need a corresponding test in `tests/`.
4. Run `pytest` and `pylint` locally before opening the PR — CI will catch it either way, but it's faster to know upfront.
5. Open the PR against `main`. Describe *why*, not just *what* — the diff already shows what changed.
6. Address review feedback with new commits; don't force-push over review history mid-review.

## Code style

- Follow the pylint configuration already in the repo (`pylintrc` if present, otherwise defaults) — CI fails under score 8.0.
- No `print()` calls in analyzer business logic (`src/analyzers/*.py`) — output goes through the display layer (`src/core/result_formatter.py`) via `ThreadAwareStdoutRouter`. This keeps module output thread-safe and testable.
- Every analyzer module returns a plain `dict` — no custom exceptions escaping to the orchestrator. Failures are represented as `analysis_status` values (`'erfolgreich'`/`'fehlgeschlagen'`/`'quota_exceeded'`/`'skipped'`), not raised exceptions, except where `_call_module_function()` in `src/core/domain_analyzer.py` explicitly wraps a module call in try/except.
- Prefer extending an existing analyzer over adding a new orchestrator branch — check `src/analyzers/` first for a module that already owns the relevant data source.

## Adding a new analyzer module

1. Add `src/analyzers/<name>_analyzer.py` (or `<name>_client.py` for a thin API wrapper) returning a result `dict`.
2. Register it in the module execution order in `src/core/domain_analyzer.py` and add a timeout entry to `MODULE_TIMEOUTS` in `config/settings.py`.
3. Add a display block for it in `src/core/result_formatter.py`.
4. Add unit tests under `tests/test_<name>_analyzer.py` with mocked HTTP responses — no live network calls in tests.
5. Update the module list and report block order in `CLAUDE.md` and `README.md`.

## Reporting bugs / requesting features

Open a GitHub issue. Include the domain you tested against (or `example.com`/`github.com` if the target is sensitive), the report block affected, and — for bugs — the relevant excerpt from `reports/raw/<id>_<domain>.txt`.
