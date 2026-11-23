/**
 * Validates that an external link URL uses an explicit http: or https: scheme
 * before rendering it in an anchor href, blocking javascript:, data:, vbscript:,
 * and other executable or local schemes from scraped OSINT sources.
 */
export function toSafeExternalUrl(rawUrl: string | null | undefined): string | undefined {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
    return undefined;
  } catch {
    return undefined;
  }
}
