/** Global reactive stores for the app. */
import { writable, derived } from 'svelte/store';
import type { Profile, Device, SSEEvent, SmartProtocolStatus, ToastMessage, AppStatus } from '../types';
import { api } from '../api';

export const appStatus = writable<AppStatus>('loading');
export const profiles = writable<Profile[]>([]);
export const devices = writable<Device[]>([]);
export const protonLoggedIn = writable<boolean>(false);
export const toastMessage = writable<ToastMessage | null>(null);
export const movingDevices = writable<Set<string>>(new Set());
export const smartProtocolStatus = writable<Record<string, SmartProtocolStatus>>({});

// SSE connection
let sseSource: EventSource | null = null;

export function startSSE(): void {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/stream');
  sseSource.onmessage = (e: MessageEvent) => {
    try {
      const data: SSEEvent = JSON.parse(e.data);
      if (data.tunnel_health || data.kill_switch || data.profile_names) {
        profiles.update(list => {
          if (data.tunnel_health) {
            for (const [pid, h] of Object.entries(data.tunnel_health)) {
              const p = list.find(x => x.id === pid);
              if (p) p.health = h;
            }
          }
          if (data.kill_switch) {
            for (const [pid, ks] of Object.entries(data.kill_switch)) {
              const p = list.find(x => x.id === pid);
              if (p) p.kill_switch = ks;
            }
          }
          if (data.profile_names) {
            for (const [pid, name] of Object.entries(data.profile_names)) {
              const p = list.find(x => x.id === pid);
              if (p && name) p.name = name;
            }
          }
          if (data.server_info) {
            for (const [pid, srv] of Object.entries(data.server_info)) {
              const p = list.find(x => x.id === pid);
              if (p) p.server = srv;
            }
          }
          return [...list];
        });
      }
      if (data.devices) {
        devices.set(data.devices);
      }
      if (data.smart_protocol_status !== undefined) {
        smartProtocolStatus.set(data.smart_protocol_status);
      }
    } catch {}
  };
}

export function stopSSE(): void {
  if (sseSource) { sseSource.close(); sseSource = null; }
}

export function showToast(text: string, error = false): void {
  toastMessage.set({ text, error });
  setTimeout(() => toastMessage.set(null), 3500);
}

/** Reload profiles and devices from the API. Replaces duplicated fetch+set blocks. */
export async function reloadData(): Promise<void> {
  const [p, d] = await Promise.all([api.getProfiles(), api.getDevices()]);
  profiles.set(p);
  devices.set(d);
}

// Derived stores
export const unassignedDevices = derived(devices, ($d: Device[]) => $d.filter(d => !d.profile_id));

export function devicesForProfile(profileId: string): Device[] {
  let result: Device[] = [];
  devices.subscribe(d => { result = d.filter(x => x.profile_id === profileId); })();
  return result;
}
