# FlintVPN Manager — Frontend

Svelte 5 + Vite SPA served by the Flask backend at `http://<host-ip>:5000`. Not a standalone app — it talks to the Python backend via the REST API documented in [`../docs/rest-api.md`](../docs/rest-api.md) and receives live updates over SSE.

See the top-level [README](../README.md) for the full project overview, installation, and disclaimer.

## Layout

```
src/
  App.svelte                 Router + top-level layout
  app.css                    Design tokens (consume via var(--token-name))
  lib/
    api.js                   fetch wrapper (throws on !res.ok)
    stores/                  Svelte stores + SSE handler
    device-utils.js, format.js, country.js, emojiData.js
  components/                Dashboard, GroupCard, ServerPicker, DeviceModal, …
  __tests__/                 Vitest unit tests
e2e/                         Playwright E2E specs (require backend on :5000)
```

See [`../docs/internals/frontend.md`](../docs/internals/frontend.md) for the component-by-component breakdown and [`../docs/internals/design-system.md`](../docs/internals/design-system.md) for the Sentry-inspired design reference.

## Development

```bash
# Hot-reload dev server (proxies API to :5000, requires backend running)
npm run dev            # → http://localhost:5173

# Production build — Flask serves the output from ../static/
npm run build

# Unit tests (vitest, excludes e2e)
npm test

# E2E tests (Playwright — needs backend running on :5000)
npx playwright test
npx playwright test --ui     # interactive
```

**Rebuild before browser-testing against the Flask server** — Flask serves static files from `../static/` directly. The `:5173` dev server is only for interactive development.

## Design tokens

Never hardcode colors, fonts, shadows, or radii in component `<style>` blocks. Use `var(--token-name)` from `src/app.css` `:root`. Buttons use uppercase text with `letter-spacing: 0.2px`. Full reference in [`../docs/internals/design-tokens.md`](../docs/internals/design-tokens.md).
