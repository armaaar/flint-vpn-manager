<script>
  import { onMount } from 'svelte';
  import { api } from './lib/api';
  import { appStatus, profiles, devices, protonLoggedIn, startSSE } from './lib/stores/app';
  import SetupScreen from './screens/SetupScreen.svelte';
  import UnlockScreen from './screens/UnlockScreen.svelte';
  import Dashboard from './screens/Dashboard.svelte';
  import Toast from './lib/components/ui/Toast.svelte';

  onMount(async () => {
    const status = await api.getStatus();
    if (status.status === 'setup-needed') {
      appStatus.set('setup-needed');
    } else if (status.status === 'locked') {
      appStatus.set('locked');
    } else {
      appStatus.set('unlocked');
      const [p, d] = await Promise.all([api.getProfiles(), api.getDevices()]);
      profiles.set(p);
      devices.set(d);
      protonLoggedIn.set(status.proton_logged_in || false);
      startSSE();
    }
  });
</script>

{#if $appStatus === 'loading'}
  <div class="loading-screen">
    <div class="spinner-lg"></div>
  </div>
{:else if $appStatus === 'setup-needed'}
  <SetupScreen />
{:else if $appStatus === 'locked'}
  <UnlockScreen />
{:else}
  <Dashboard />
{/if}

<Toast />

<style>
  .loading-screen { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: var(--bg); }
  .spinner-lg { width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
