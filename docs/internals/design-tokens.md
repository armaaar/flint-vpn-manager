# Design Tokens

All design tokens live as CSS custom properties in `frontend/src/app.css` `:root`. Components reference tokens via `var(--token-name)` — never hardcode raw values.

## Token Catalog

### Fonts
| Token | Value | Usage |
|-------|-------|-------|
| `--font-ui` | Rubik, system fallbacks | All UI text |
| `--font-mono` | Monaco, Menlo, Ubuntu Mono | IPs, MACs, logs, code |

### Backgrounds
| Token | Value | Usage |
|-------|-------|-------|
| `--bg` | `#16131e` | Page background |
| `--bg2` | `#12101a` | Sidebar, modals, deeper sections |
| `--bg3` | `#1e1a28` | Hover states, active nav items |

### Surfaces
| Token | Value | Usage |
|-------|-------|-------|
| `--surface` | `#211d2b` | Cards, panels |
| `--surface2` | `#2a2636` | Elevated cards |

### Text
| Token | Value | Usage |
|-------|-------|-------|
| `--fg` | `#e8e6ef` | Primary text |
| `--fg2` | `#a9a4b8` | Secondary text, labels |
| `--fg3` | `#6b6580` | Muted text, placeholders |

### Accent (Interactive)
| Token | Value | Usage |
|-------|-------|-------|
| `--accent` | `#7b6fce` | Links, active states, focus rings |
| `--accent2` | `#5a4fa8` | Hover on accent elements |
| `--accent-bg` | `rgba(123,111,206,.12)` | Selected item backgrounds |

### Sentry Accents
| Token | Value | Usage |
|-------|-------|-------|
| `--lime` | `#c2ef4e` | High-visibility highlights |
| `--coral` | `#ffb287` | Warm accent, focus backgrounds |
| `--pink` | `#fa7faa` | Decorative accents |

### Semantic Colors
| Token | Value | Usage |
|-------|-------|-------|
| `--green` / `--green2` | `#2ecc71` / `#27ae60` | Connected, success |
| `--green-bg` | `rgba(46,204,113,.12)` | Success background |
| `--amber` | `#f39c12` | Connecting, warning |
| `--amber-bg` | `rgba(243,156,18,.12)` | Warning background |
| `--red` | `#e74c3c` | Error, danger |
| `--red-bg` | `rgba(231,76,60,.12)` | Error background |

### Borders
| Token | Value | Usage |
|-------|-------|-------|
| `--border` | `#2a2636` | Standard borders |
| `--border2` | `#383345` | Emphasized borders |

### Radius
| Token | Value | Usage |
|-------|-------|-------|
| `--radius` | `12px` | Cards, modals |
| `--radius-sm` | `8px` | Buttons, sections |
| `--radius-xs` | `6px` | Inputs, small elements |

### Shadows
| Token | Value | Usage |
|-------|-------|-------|
| `--shadow` | Purple-tinted subtle | Cards, default elevation |
| `--shadow-lg` | Purple-tinted deep | Modals, popovers |

### Buttons
| Token | Value | Usage |
|-------|-------|-------|
| `--btn-primary-bg` | `#79628c` | Primary button background |
| `--btn-primary-border` | `#584674` | Primary button border |
| `--btn-inset` | Inset shadow | Tactile pressed effect on buttons |
| `--btn-hover-shadow` | Elevated shadow | Button hover elevation |

### Focus
| Token | Value | Usage |
|-------|-------|-------|
| `--focus-ring` | Purple glow ring | Input/button focus state |

### Glass / Overlay
| Token | Value | Usage |
|-------|-------|-------|
| `--glass-bg` | `rgba(255,255,255,.18)` | Frosted glass surfaces |
| `--glass-hover` | `rgba(54,22,107,.14)` | Glass hover state |
| `--glass-blur` | `blur(12px) saturate(150%)` | Backdrop filter for glass |
| `--overlay-bg` | `rgba(12,10,18,.75)` | Modal overlay backdrop |

### Status Gradients
| Token | Usage |
|-------|-------|
| `--grad-connected` | Green gradient for connected tunnels |
| `--grad-reconnecting` | Amber gradient for transitioning |
| `--grad-disconnected` | Muted gradient for disconnected |
| `--grad-novpn` | Purple gradient for NoVPN groups |
| `--grad-nointernet` | Dark gradient for NoInternet groups |

### Transition
| Token | Value |
|-------|-------|
| `--transition` | `.2s ease` |

## Reskinning

To change the entire app's look, edit only the `:root` block in `frontend/src/app.css`. No component files need modification.
