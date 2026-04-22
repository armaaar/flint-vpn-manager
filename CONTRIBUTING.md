# Contributing

Thanks for your interest! This is a **solo-maintained hobby project** targeting one specific router + firmware + VPN combination (see [README.md](README.md#️-important-disclaimer--read-first)). That narrows what kinds of contributions are useful.

## What's welcome

- Bug fixes for the supported configuration
- Small, focused features that fit the project's scope (personal home-router VPN management)
- Documentation improvements and typo fixes
- Better test coverage for mockable code paths

## What's likely to be declined

- Support for other routers, firmwares, or VPN providers. The project's value comes from depth on one target, not breadth. Fork if that's what you need.
- Large redesigns without prior discussion. Please open an issue first.
- Reformatting / style-only PRs. Match the existing style.
- Features that require ongoing upstream-API babysitting (e.g. support for providers with frequently-breaking APIs).

## Ground rules

### License

By submitting a contribution, you agree it is licensed under the project's [PolyForm Noncommercial License 1.0.0](LICENSE) and that you have the right to submit it under those terms.

### Tests

- **Never add tests to CI that require a live router, live ProtonVPN session, or real credentials.** Mark them `@pytest.mark.integration` so they're excluded by the default `pytest -m "not integration"` invocation.
- Mockable unit tests should always mock the `RouterAPI` (see `tests/test_router_api.py::mock_router` fixture) and `ProtonAPI`.
- Frontend unit tests live in `frontend/src/__tests__/`. Playwright E2E tests live in `frontend/e2e/` and are not part of CI.

### Before opening a PR

```bash
# Backend: unit tests only
source venv/bin/activate
python -m pytest tests/ -m "not integration"

# Frontend: build + unit tests
cd frontend
npm run build
npm test
```

Make sure both are green. If you're touching router-interaction code, also describe how you tested it end-to-end against a real router in the PR description.

### Style

- Match the existing code. No reformatting of untouched lines.
- No new dependencies unless they meaningfully simplify something.
- Keep comments sparse — the code should read well without them. Only comment the non-obvious *why*.
- Follow the safety rules in [CLAUDE.md](CLAUDE.md#router-interaction-safety-rules).

## Development

### Initial setup

Follow [docs/installation.md](docs/installation.md) to get the backend + frontend running. The same `--system-site-packages` venv works for development.

### Common commands

```bash
# Backend with hot-reload (Flask debug)
source venv/bin/activate && python backend/app.py

# Frontend dev server (hot reload, proxies API to :5000)
cd frontend && npm run dev     # → http://localhost:5173

# Backend unit tests (no router, no Proton creds) — the CI default
source venv/bin/activate && python -m pytest tests/ -m "not integration"

# Backend integration tests (requires live router on 192.168.8.1)
python -m pytest tests/ -m integration

# Frontend unit tests (vitest)
cd frontend && npm test

# Frontend E2E tests (Playwright — needs backend running on :5000)
cd frontend && npx playwright test
```

**Important:** The frontend **must be rebuilt** (`cd frontend && npm run build`) before testing in a browser against the Flask server. Flask serves the contents of `static/` directly; the dev server on :5173 is only for interactive development.

### Where to put new code

Architecture guidance lives in [docs/internals/backend-structure.md](docs/internals/backend-structure.md) and [docs/internals/backend-modules.md](docs/internals/backend-modules.md). Before adding a new module, check those for the intended layering.
