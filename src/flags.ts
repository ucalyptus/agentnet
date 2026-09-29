// AGENTNET_CELLD=1 selects celld (self-hosted Durable Objects) instead of Cloudflare, both
// for the dev/deploy scripts and for the client's default server. Unset or 0 is off, so a
// host that never sets it keeps the Cloudflare service.
export const CELLD_DEV_PORT = 8799;
export const CELLD_DEV_SERVER = `http://127.0.0.1:${CELLD_DEV_PORT}`;

export function celldEnabled(value = process.env.AGENTNET_CELLD): boolean {
  if (value === undefined || value === '0') return false;
  if (value === '1') return true;
  throw new Error('AGENTNET_CELLD must be 0 or 1.');
}
