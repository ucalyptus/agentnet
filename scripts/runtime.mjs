// Runs `dev` or `deploy` on celld when AGENTNET_CELLD=1 (from the environment or a local
// .env), otherwise on Cloudflare through Wrangler. Extra arguments pass through.
import { spawnSync } from 'node:child_process';
import { CELLD_DEV_PORT, celldEnabled } from '../src/flags.ts';

const [task, ...extra] = process.argv.slice(2);
const celld = celldEnabled();
const commands = {
  dev: celld
    ? ['celld', ['dev', 'celld.jsonc', '--host', '127.0.0.1', '--port', String(CELLD_DEV_PORT)]]
    : ['wrangler', ['dev', '-c', 'wrangler.dev.jsonc', '--ip', '127.0.0.1']],
  deploy: celld ? ['celld', ['deploy', 'celld.jsonc']] : ['wrangler', ['deploy']],
};
if (!Object.hasOwn(commands, task)) {
  console.error('Usage: node scripts/runtime.mjs dev|deploy [ARGS...]');
  process.exit(2);
}
const [command, args] = commands[task];
console.error(`agentnet ${task}: ${celld ? 'celld (AGENTNET_CELLD=1)' : 'Cloudflare'}`);
const result = spawnSync(command, [...args, ...extra], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
