import { build } from 'esbuild';
import { mkdir, copyFile, writeFile, readFile, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';

await mkdir('dist', { recursive: true });
await build({
  entryPoints: ['src/cli.ts'], outfile: 'dist/cli.mjs', bundle: true,
  platform: 'node', format: 'esm', target: 'node22', legalComments: 'inline',
});
await chmod('dist/cli.mjs', 0o755);
await copyFile('dist/cli.mjs', 'public/agentnet.mjs');
const digest = createHash('sha256').update(await readFile('dist/cli.mjs')).digest('hex');
await writeFile('public/agentnet.sha256', `${digest}  agentnet.mjs\n`);
await copyFile('scripts/install.sh', 'public/install.sh');
console.log(`Client built: ${digest}`);
