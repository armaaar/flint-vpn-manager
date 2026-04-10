/** Global reactive stores for the app. */
import { writable, derived } from 'svelte/store';

export const appStatus = writable('loading'); // 'loading' | 'setup-needed' | 'locked' | 'unlocked'
export const profiles = writable([]);
export const devices = writable([]);
export const protonLoggedIn = writable(false);
export const toastMessage = writable(null); // { text, error }
export const movingDevices = writable(new Set()); // MACs of devices being reassigned
export const smartProtocolStatus = writable({}); // {profile_id: {attempting, attempt, total, elapsed}}

// SSE connection
let sseSource = null;

export function startSSE() {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/stream');
  sseSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      // Tunnel health, kill switch, and profile names are pulled live from the
      // router every tick. No local cache: the UI displays whatever the SSE
      // event reports.
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

export function stopSSE() {
  if (sseSource) { sseSource.close(); sseSource = null; }
}

export function showToast(text, error = false) {
  toastMessage.set({ text, error });
  setTimeout(() => toastMessage.set(null), 3500);
}

// Derived stores
export const unassignedDevices = derived(devices, $d => $d.filter(d => !d.profile_id));

export function devicesForProfile(profileId) {
  let result = [];
  devices.subscribe(d => { result = d.filter(x => x.profile_id === profileId); })();
  return result;
}
