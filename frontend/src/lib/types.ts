/** Shared TypeScript types for the FlintVPN frontend. */

// ── Profile Types ──────────────────────────────────────────────────────────

export type ProfileType = 'vpn' | 'no_vpn' | 'no_internet';
export type HealthStatus = 'green' | 'amber' | 'red' | 'connecting' | 'loading' | 'unknown';
export type VpnProtocol = 'wireguard' | 'wireguard-tcp' | 'wireguard-tls' | 'openvpn';

export interface VpnOptions {
  netshield?: number;         // 0 | 1 | 2
  moderate_nat?: boolean;
  nat_pmp?: boolean;
  vpn_accelerator?: boolean;
  smart_protocol?: boolean;
  port?: number;
  custom_dns?: string;
  ovpn_protocol?: string;     // 'udp' | 'tcp'
}

export interface RouterInfo {
  rule_name: string;
  vpn_protocol: string;
  peer_id?: string;
  peer_num?: string;
  client_id?: string;
  client_uci_id?: string;
  group_id?: string;
  tunnel_id?: number;
  tunnel_name?: string;
  ipset_name?: string;
  ipv6?: boolean;
}

export interface ServerInfo {
  id: string;
  name: string;
  country: string;
  country_code: string;
  city: string;
  load: number;
  score?: number;
  endpoint?: string;
  entry_country_code?: string;
  physical_server_domain?: string;
  protocol?: string;
  features?: string[];
  p2p?: boolean;
  streaming?: boolean;
  secure_core?: boolean;
  tor?: boolean;
  ipv6?: boolean;
  enabled?: boolean;
  // UI-added fields
  blacklisted?: boolean;
  favourite?: boolean;
  latency?: number | null;
}

export interface ServerScope {
  country?: string;
  city?: string;
  server_id?: string;
  feature?: string;
}

export interface Profile {
  id: string;
  type: ProfileType;
  name: string;
  color: string;
  icon: string;
  is_guest: boolean;
  health?: HealthStatus;
  kill_switch?: boolean;
  server?: ServerInfo;
  server_id?: string;
  server_scope?: ServerScope;
  options?: VpnOptions;
  router_info?: RouterInfo;
  device_count: number;
  display_order?: number;
  adblock?: boolean;
  wg_key?: string;
  cert_expiry?: string;
  _orphan?: boolean;
  _ghost?: boolean;
}

// ── Device Types ───────────────────────────────────────────────────────────

export interface Device {
  mac: string;
  ip: string;
  display_name: string;
  hostname: string;
  device_class: string;
  label: string;
  profile_id: string | null;
  iface: string;
  network: string;
  network_zone: string;
  router_online: boolean;
  last_seen: string | null;
  signal_dbm: number | null;
  link_speed_mbps: number | null;
  rx_speed: number;
  tx_speed: number;
  total_rx: number;
  total_tx: number;
  ipv6_addresses?: string[];
  // DnD requires an id field
  id?: string;
}

// ── SSE Event ──────────────────────────────────────────────────────────────

export interface SSEEvent {
  tunnel_health?: Record<string, HealthStatus>;
  kill_switch?: Record<string, boolean>;
  profile_names?: Record<string, string>;
  server_info?: Record<string, ServerInfo>;
  devices?: Device[];
  device_count?: number;
  smart_protocol_status?: Record<string, SmartProtocolStatus>;
  timestamp?: number;
  error?: string;
}

export interface SmartProtocolStatus {
  attempting: string;
  attempt: number;
  total: number;
  elapsed?: number;
}

// ── Settings Types ─────────────────────────────────────────────────────────

export interface AppSettings {
  router_ip: string;
  alternative_routing?: boolean;
  global_ipv6_enabled?: boolean;
  auto_optimize?: {
    enabled: boolean;
    time: string;
  };
  server_blacklist?: string[];
  server_favourites?: string[];
  adblock?: AdblockSettings;
}

export interface AdblockSettings {
  blocklist_sources?: string[];
  custom_domains?: string[];
  last_updated?: string;
  domain_count?: number;
  presets?: Record<string, { name: string; url: string; description: string }>;
}

// ── LAN Access Types ───────────────────────────────────────────────────────

export interface LanNetwork {
  zone_id: string;
  name: string;
  subnet: string;
  ssids?: LanSSID[];
  device_count?: number;
  enabled?: boolean;
  isolated?: boolean;
  ipv6_enabled?: boolean;
  is_lan?: boolean;
  is_guest?: boolean;
}

export interface LanSSID {
  iface: string;
  ssid: string;
  band: string;
  encryption: string;
  key: string;
  hidden: boolean;
  disabled: boolean;
}

export interface AccessRule {
  src: string;
  dest: string;
  allowed: boolean;
}

export interface LanException {
  id: string;
  from_type: string;
  from_id: string;
  from_label?: string;
  to_type: string;
  to_id: string;
  to_label?: string;
  direction: string;
}


// ── Toast ──────────────────────────────────────────────────────────────────

export interface ToastMessage {
  text: string;
  error: boolean;
}

// ── App Status ─────────────────────────────────────────────────────────────

export type AppStatus = 'loading' | 'setup-needed' | 'locked' | 'unlocked';
