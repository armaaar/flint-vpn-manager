<script>
  import { toastMessage } from '../stores/app.js';
</script>

{#if $toastMessage}
  <div class="toast" class:error={$toastMessage.error}>
    {$toastMessage.text}
  </div>
{/if}

<style>
  .toast {
    position: fixed; bottom: 24px; right: 24px;
    background: var(--surface); color: var(--fg);
    padding: 14px 24px; border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg); z-index: 300;
    animation: toastIn .3s ease; font-size: .9rem;
    border-left: 4px solid var(--green); max-width: 360px;
  }
  .toast.error { border-left-color: var(--red); }
  @keyframes toastIn { from { transform: translateY(16px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
</style>
