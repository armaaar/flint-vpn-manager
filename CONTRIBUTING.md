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

## Development setup

See the [Development](README.md#development) section of the README.
