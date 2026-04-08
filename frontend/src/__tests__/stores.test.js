import { describe, it, expect, vi } from 'vitest';
import { get } from 'svelte/store';
import { profiles, devices, appStatus, unassignedDevices, showToast, toastMessage } from '../lib/stores/app.js';

describe('appStatus store', () => {
  it('defaults to loading', () => {
    expect(get(appStatus)).toBe('loading');
  });

  it('can be set', () => {
    appStatus.set('unlocked');
    expect(get(appStatus)).toBe('unlocked');
    appStatus.set('loading'); // reset
  });
});

describe('profiles store', () => {
  it('defaults to empty', () => {
    expect(get(profiles)).toEqual([]);
  });

  it('can store profiles', () => {
    profiles.set([{ id: '1', name: 'Test' }]);
    expect(get(profiles)).toHaveLength(1);
    profiles.set([]); // reset
  });
});

describe('devices store', () => {
  it('defaults to empty', () => {
    expect(get(devices)).toEqual([]);
  });
});

describe('unassignedDevices derived store', () => {
  it('filters devices with no profile_id', () => {
    devices.set([
      { mac: 'aa:bb:cc:dd:ee:ff', profile_id: 'p1' },
      { mac: '11:22:33:44:55:66', profile_id: null },
      { mac: '77:88:99:aa:bb:cc', profile_id: null },
    ]);
    expect(get(unassignedDevices)).toHaveLength(2);
    expect(get(unassignedDevices)[0].mac).toBe('11:22:33:44:55:66');
    devices.set([]); // reset
  });
});

describe('showToast', () => {
  it('sets and clears toast message', async () => {
    vi.useFakeTimers();
    showToast('Test message');
    expect(get(toastMessage)).toEqual({ text: 'Test message', error: false });

    showToast('Error!', true);
    expect(get(toastMessage)).toEqual({ text: 'Error!', error: true });

    vi.advanceTimersByTime(4000);
    expect(get(toastMessage)).toBeNull();
    vi.useRealTimers();
  });
});
