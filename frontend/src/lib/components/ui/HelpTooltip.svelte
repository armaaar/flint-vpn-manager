<script>
  /**
   * Help tooltip with rich content. Renders a small `?` icon; on hover or
   * click it shows a styled popover positioned relative to the viewport
   * (so it can escape an overflow:hidden modal). Auto-flips left/right and
   * up/down based on available space.
   *
   * Keep slot content short — 2-3 sentences max.
   */
  export let title = '';

  let open = false;
  let trigger;
  let popover;
  let popStyle = '';

  const POPOVER_WIDTH = 260;
  const MARGIN = 8;

  function position() {
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    // Estimate height — actual is measured in updatePosition after render
    let top = rect.top + rect.height / 2;
    // Prefer right of trigger; flip to left if not enough room
    let left = rect.right + MARGIN;
    if (left + POPOVER_WIDTH > vw - MARGIN) {
      left = rect.left - POPOVER_WIDTH - MARGIN;
    }
    // Final clamp: never bleed off the left edge
    if (left < MARGIN) left = MARGIN;
    popStyle = `top:${top}px;left:${left}px;`;
  }

  function updatePosition() {
    if (!popover || !trigger) return;
    const popRect = popover.getBoundingClientRect();
    const trigRect = trigger.getBoundingClientRect();
    const vh = window.innerHeight;
    const vw = window.innerWidth;
    // Vertically: center on trigger, then clamp to viewport
    let top = trigRect.top + trigRect.height / 2 - popRect.height / 2;
    if (top < MARGIN) top = MARGIN;
    if (top + popRect.height > vh - MARGIN) top = vh - popRect.height - MARGIN;
    // Horizontally: prefer right, flip to left
    let left = trigRect.right + MARGIN;
    if (left + popRect.width > vw - MARGIN) {
      left = trigRect.left - popRect.width - MARGIN;
    }
    if (left < MARGIN) left = MARGIN;
    popStyle = `top:${top}px;left:${left}px;`;
  }

  function show() {
    open = true;
    position();
    // Re-measure after the popover is rendered to get the actual height
    queueMicrotask(updatePosition);
  }
  function hide() { open = false; }
  function toggle(e) {
    e.stopPropagation();
    if (open) hide();
    else show();
  }

  function handleWindowClick(e) {
    if (!open) return;
    if (trigger && !trigger.contains(e.target) &&
        popover && !popover.contains(e.target)) {
      open = false;
    }
  }
</script>

<svelte:window on:click={handleWindowClick} on:resize={updatePosition} />

<span class="tooltip-wrap"
      bind:this={trigger}
      on:mouseenter={show}
      on:mouseleave={hide}>
  <button type="button" class="tooltip-btn"
          on:click={toggle}
          on:focus={show}
          on:blur={hide}
          aria-label={title ? `Help: ${title}` : 'Help'}>?</button>
</span>

{#if open}
  <div class="tooltip-popover"
       bind:this={popover}
       style={popStyle}
       on:click|stopPropagation
       on:mouseenter={show}
       on:mouseleave={hide}>
    {#if title}<div class="tooltip-title">{title}</div>{/if}
    <div class="tooltip-body">
      <slot />
    </div>
  </div>
{/if}

<style>
  .tooltip-wrap {
    display: inline-flex;
    align-items: center;
  }
  .tooltip-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--border);
    color: var(--fg3);
    font-size: .65rem;
    font-weight: 700;
    cursor: help;
    border: none;
    padding: 0;
    margin-left: 6px;
  }
  .tooltip-btn:hover { background: var(--accent); color: #fff; }
  .tooltip-btn:focus { outline: 2px solid var(--accent); outline-offset: 1px; }

  .tooltip-popover {
    position: fixed;
    z-index: 500;
    width: 260px;
    max-width: calc(100vw - 16px);
    background: var(--surface);
    border: 1px solid var(--border2);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg);
    padding: 10px 12px;
    font-size: .78rem;
    line-height: 1.45;
    color: var(--fg2);
    text-align: left;
    cursor: default;
    pointer-events: auto;
  }
  .tooltip-title {
    font-size: .82rem;
    font-weight: 600;
    color: var(--fg);
    margin-bottom: 4px;
  }
  .tooltip-body :global(p) {
    margin: 0;
  }
</style>
