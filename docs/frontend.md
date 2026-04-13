# Frontend (Svelte + Vite)

Built with Svelte 5 + Vite. Source in `frontend/src/`, builds to `static/`.

## Components

| Component | Purpose |
|-----------|---------|
| `Dashboard.svelte` | Sidebar + group cards (DnD reorderable) + unassigned devices section |
| `GroupCard.svelte` | Aircove-style card: gradient header, server info, connect/disconnect button, collapsible VPN options panel, device list (DnD) |
| `DeviceRow.svelte` | Device in a group: icon, name, online dot, IP, speed, signal, private-MAC badge |
| `DeviceModal.svelte` | Device settings: custom name, device type (synced to router gl-client), group assignment |
| `GroupModal.svelte` | Unified create/edit group modal. Same field order in both modes: type → protocol → VPN options → name → icon/color → guest. Create mode opens ServerPicker for VPN groups. Edit mode handles protocol change, type change (VPN ↔ NoVPN ↔ NoInternet), and VPN option regeneration on Save. |
| `ServerPicker.svelte` | 3-level server browser: Country → City → Server. Filters, scope selector. Per-server star (favourite) and ban (blacklist) toggles. "Test latency" button probes from router and shows color-coded ms badges (green <50ms, yellow <150ms, red >=150ms). Blacklisted servers dimmed + strikethrough + sorted last. Favourites sorted first. |
| `LanAccessPage.svelte` | Top-level page (`#lan-access`): network cards (collapsible) with isolation toggle, create/delete network, cross-network access rules table (inbound/outbound per zone pair), SSE-reactive device list per network (derived from global `$devices` store via `network_zone` field), exceptions section. Shows WiFi restart warning modals before disruptive actions (driver reload for create/delete, `wifi reload` for enable/disable/isolation/SSID changes). |
| `ExceptionModal.svelte` | Modal for adding device exceptions: From/To pickers (device or entire network), direction selector (both/outbound/inbound) |
| `EmojiPicker.svelte` | Categorized emoji grid with search |
| `ColorPicker.svelte` | Color selection for card accent |
| `SettingsModal.svelte` | Router IP, auto-optimize schedule, server preferences (blacklist/favourites counts + clear all), credentials, master password change |
| `LogsModal.svelte` | Live log viewer (app.log, error.log, access.log) with tabs |
| `SetupScreen.svelte` | First-time credential setup |
| `UnlockScreen.svelte` | Master password entry |
| `Toast.svelte` | Notification toasts |

## Stores (`frontend/src/lib/stores/app.js`)

Writable: `profiles`, `devices`, `appStatus`, `protonLoggedIn`, `toastMessage`, `movingDevices`, `smartProtocolStatus`. Derived: `unassignedDevices`. SSE handler mutates `p.health`, `p.kill_switch`, `p.name`, `p.server` from each event.

## API Client (`frontend/src/lib/api.js`)

One function per Flask endpoint via `fetch()`.
