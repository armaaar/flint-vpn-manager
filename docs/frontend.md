# Frontend (Svelte 5 + Vite + TypeScript)

Built with Svelte 5, Vite 8, and TypeScript. Source in `frontend/src/`, builds to `static/`.

## Directory Structure

```
src/
├── app.css                              # Global design tokens + layout styles
├── App.svelte                           # Entry: status check → Setup/Unlock/Dashboard
├── main.js                              # Vite entry point
│
├── screens/                             # Full-page views
│   ├── Dashboard.svelte                 # Main shell: sidebar + group cards + DnD + hash routing
│   ├── SetupScreen.svelte               # First-time credential setup
│   └── UnlockScreen.svelte              # Master password entry
│
├── lib/
│   ├── types.ts                         # Shared TypeScript interfaces (Profile, Device, Server, etc.)
│   ├── api.ts                           # Typed REST client (all fetch calls to Flask backend)
│   ├── emojiData.js                     # Emoji categories + keywords for picker
│   │
│   ├── stores/
│   │   └── app.ts                       # Global stores: profiles, devices, SSE, toast, reloadData()
│   │
│   ├── utils/
│   │   ├── format.ts                    # timeAgo, formatBytes, formatSpeed, loadBarColor
│   │   ├── device.ts                    # isOnline, isStale, deviceIcon, DEVICE_TYPES
│   │   ├── country.ts                   # countryFlag, countryFlagUrl, countryName
│   │   ├── color.ts                     # hexToHSL, buildGradient (extracted from GroupCard)
│   │   ├── profile.ts                   # derivedConnState, getStatusClass/Label/BorderColor
│   │   └── index.ts                     # Barrel re-export for backward compatibility
│   │
│   └── components/
│       ├── ui/                          # Reusable building blocks
│       │   ├── HelpTooltip.svelte       # Info popover (hover/click, auto-position)
│       │   ├── Toast.svelte             # Notification toast (driven by toastMessage store)
│       │   ├── EmojiPicker.svelte       # Categorized emoji grid with search
│       │   └── ColorPicker.svelte       # Color palette + custom hex input
│       │
│       ├── devices/
│       │   └── DeviceRow.svelte         # Device list item: icon, name, online dot, speed
│       │
│       ├── groups/
│       │   ├── GroupCard.svelte         # Profile card: gradient header, server, connect/disconnect, DnD devices
│       │   └── GroupModal.svelte        # Create/edit profile: type, protocol, VPN options, name, icon, color
│       │
│       ├── server/
│       │   └── ServerPicker.svelte      # 3-level server browser: Country → City → Server
│       │
│       ├── settings/
│       │   ├── SettingsPage.svelte      # Tab shell (~75 lines, routes to tab components)
│       │   ├── GeneralTab.svelte        # Router IP, alternative routing
│       │   ├── ServersTab.svelte        # Auto-optimize, server preferences
│       │   ├── AdblockTab.svelte        # Blocklist presets, custom URLs/domains, domain viewer
│       │   ├── SessionsTab.svelte       # Active VPN sessions list
│       │   └── SecurityTab.svelte       # Update credentials, change master password
│       │
│       ├── lan/
│       │   ├── LanAccessPage.svelte     # Network cards, WiFi settings, access rules, exceptions
│       │   └── ExceptionModal.svelte    # LAN access exception editor
│       │
│       └── modals/
│           ├── DeviceModal.svelte       # Device detail: label, type, group assignment
│           └── LogsModal.svelte         # Log viewer with tabs (app.log, error.log, access.log)
│
└── __tests__/                           # Vitest unit tests
    ├── api.test.js
    ├── stores.test.js
    └── utils.test.js
```

## TypeScript

The frontend uses TypeScript for all utility/store/API modules. Svelte components are incrementally migrated to `<script lang="ts">`.

- **`types.ts`** — Shared interfaces: `Profile`, `Device`, `ServerInfo`, `RouterInfo`, `VpnOptions`, `SSEEvent`, `AppSettings`, `LanNetwork`, `LanException`, etc.
- **`api.ts`** — Every API method has typed return values (e.g., `getProfiles(): Promise<Profile[]>`)
- **`stores/app.ts`** — Typed writable stores (`writable<Profile[]>`, `writable<Device[]>`)
- **`utils/*.ts`** — All utility functions have typed parameters and return values

## Stores (`lib/stores/app.ts`)

| Store | Type | Purpose |
|-------|------|---------|
| `appStatus` | `AppStatus` | `'loading' \| 'setup-needed' \| 'locked' \| 'unlocked'` |
| `profiles` | `Profile[]` | All profiles (VPN + non-VPN) |
| `devices` | `Device[]` | All devices (SSE-updated every 10s) |
| `protonLoggedIn` | `boolean` | Whether Proton API session is active |
| `toastMessage` | `ToastMessage \| null` | Current toast notification |
| `movingDevices` | `Set<string>` | MACs of devices being drag-dropped |
| `smartProtocolStatus` | `Record<string, SmartProtocolStatus>` | Smart protocol retry state per profile |

**Derived:** `unassignedDevices` — devices with no `profile_id`.

**Functions:** `startSSE()`, `stopSSE()`, `showToast(text, error?)`, `reloadData()`, `devicesForProfile(id)`.

## API Client (`lib/api.ts`)

Typed `fetch()` wrapper. One method per Flask endpoint. All methods return typed promises. Error responses throw `Error` with the backend's error message.

## Design Tokens (`app.css`)

Sentry-inspired dark theme. All colors, fonts, shadows, and radii defined as CSS custom properties in `:root`. Components use `var(--token)` — never hardcode values. See [design-tokens.md](design-tokens.md).

## Routing

Hash-based routing in `Dashboard.svelte`:
- `#/` or `#` → Dashboard view (group cards)
- `#networks` → LanAccessPage
- `#settings` or `#settings/{tab}` → SettingsPage

## Key Patterns

- **SSE for live updates**: `startSSE()` subscribes to `/api/stream`. Updates health, kill switch, names, servers, and devices every 10s.
- **Drag-and-drop**: `svelte-dnd-action` for group reordering and device assignment.
- **Optimistic UI**: Connect/disconnect updates health to `'connecting'` immediately, before the API response.
- **`reloadData()`**: Centralized profiles+devices fetch. Replaces duplicated `Promise.all([getProfiles, getDevices])` blocks.
