import { build } from 'esbuild';
import { mkdir, copyFile, writeFile, readFile, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const { version } = JSON.parse(await readFile('package.json', 'utf8'));
await mkdir('dist', { recursive: true });
await build({
  entryPoints: ['src/cli.ts'], outfile: 'dist/cli.mjs', bundle: true,
  platform: 'node', format: 'esm', target: 'node22', legalComments: 'inline',
  define: { __AGENTNET_VERSION__: JSON.stringify(version) },
});
await chmod('dist/cli.mjs', 0o755);
await copyFile('dist/cli.mjs', 'public/agentnet.mjs');
const digest = createHash('sha256').update(await readFile('dist/cli.mjs')).digest('hex');
await writeFile('public/agentnet.sha256', `${digest}  agentnet.mjs\n`);
// Sign {version,sha256} with the administrator key when it is available on this machine.
// Agents verify this against the admin key they pinned at enrollment, so a compromised
// origin cannot ship a client on its own. Builds without the key stay unsigned.
const manifest = { version, sha256: digest };
let signature = null;
const adminIdentityPath = process.env.AGENTNET_ADMIN_IDENTITY ?? 'admin-home/identity.json';
try {
  const admin = JSON.parse(await readFile(adminIdentityPath, 'utf8'));
  const { signManifest } = await import('../src/protocol.ts');
  signature = await signManifest(admin, manifest);
} catch (error) {
  console.warn(`Manifest NOT signed (${adminIdentityPath} unavailable): ${error.code ?? error.message}`);
}
await writeFile('public/version.json', JSON.stringify({ ...manifest, bundle: '/agentnet.mjs', signature }) + '\n');
await copyFile('scripts/install.sh', 'public/install.sh');
console.log(`Client built: ${version} ${digest} ${signature ? 'signed' : 'UNSIGNED'}`);
