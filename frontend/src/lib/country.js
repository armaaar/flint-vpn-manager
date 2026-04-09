/** Country code, flag, and name utility functions. */

/**
 * Convert a 2-letter country code to a flag emoji.
 * Includes special cases for codes that don't map to standard regional indicators.
 */
const FLAG_OVERRIDES = { 'UK': 'GB' };

export function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  const upper = FLAG_OVERRIDES[code.toUpperCase()] || code.toUpperCase();
  const emoji = String.fromCodePoint(
    ...upper.split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
  return emoji;
}

/**
 * Get a flag image URL from flagcdn.com for reliable cross-platform rendering.
 * Returns a small 20x15 PNG URL for the given 2-letter country code.
 */
export function countryFlagUrl(code) {
  if (!code || code.length !== 2) return '';
  const lower = (FLAG_OVERRIDES[code.toUpperCase()] || code).toLowerCase();
  return `https://flagcdn.com/20x15/${lower}.png`;
}

/**
 * Find full country name from server data. Falls back to code.
 */
export function countryName(code, servers) {
  if (!code || !servers) return code || '';
  const s = servers.find(s => s.country_code === code || s.entry_country_code === code);
  return s ? s.country : code;
}
