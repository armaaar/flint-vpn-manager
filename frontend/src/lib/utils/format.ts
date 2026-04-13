/** Formatting and display utility functions. */

/**
 * Parse an ISO timestamp as UTC.
 * Timestamps from the backend are UTC but may lack a 'Z' suffix.
 */
export function parseUTC(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const ts = iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z';
  return new Date(ts);
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const t = parseUTC(iso);
  if (!t) return 'never';
  const s = (Date.now() - t.getTime()) / 1000;
  if (s < 60) return 'Just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

export function formatBytes(b: number): string {
  if (!b || b < 1) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(1) + ' GB';
}

export function formatSpeed(bps: number): string {
  if (!bps || bps < 1) return '';
  if (bps < 1024) return bps + ' B/s';
  if (bps < 1048576) return (bps / 1024).toFixed(0) + ' KB/s';
  return (bps / 1048576).toFixed(1) + ' MB/s';
}

export function loadBarColor(load: number): string {
  if (load < 40) return 'var(--green)';
  if (load < 70) return 'var(--amber)';
  return 'var(--red)';
}
