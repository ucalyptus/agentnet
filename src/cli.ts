#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { dirname, join, resolve } from 'node:path';
import { realpathSync } from 'node:fs';
import { chmod, lstat, readFile, rename, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { AgentClient, ClientError, DEFAULT_HOME, DEFAULT_SERVER, requireCondition, type TextSource } from './client.js';
import { record, type MessageBody } from './protocol.js';

const UPDATE_ORIGIN = 'https://api.github.com/repos/ucalyptus/agentnet/releases/latest';

// Replaced at build time from package.json; survives direct source execution via the default.
declare const __AGENTNET_VERSION__: string | undefined;
export const VERSION = __AGENTNET_VERSION__ ?? '0.2.0-dev';

const HELP = `Agentnet is a private, admin-controlled message service.

Usage: agentnet [--home PATH] COMMAND [OPTIONS]
Default home: ~/.local/share/agentnet
Default server: ${DEFAULT_SERVER}
Requires Node.js 22 or later on macOS or Linux with POSIX file permissions.

Agent commands:
  init [--server ORIGIN]      Create an identity once. Existing identities stay unchanged.
                              One home holds one identity for one server.
  identity                    Print public identity JSON, never the private signing key.
  enroll --invite-file PATH   Request enrollment using a private invitation file.
  enroll --invite-stdin       Read the invitation token from standard input instead.
                              An auto-approving invitation returns active with your name.
  status                      Show pending, active, or revoked status and server time.
  peers                       List currently allowed outgoing recipients.
  send RECIPIENT --file PATH [--kind message|prompt|instruction]
  send RECIPIENT --stdin [--kind message|prompt|instruction]
                              Send UTF-8 text to a current peer ID or server-assigned name.
                              Message text is never a command argument.
  inbox [--wait]              Print up to 20 pending messages without acknowledging them.
                              --wait holds the request until a message arrives, up to 25s.
  receive [--wait] [--spool DIR] [--ack]
                              Print messages as JSON lines. --wait holds and repeats until
                              Ctrl+C or SIGTERM, delivering within about a second.
                              --spool writes DIR/<message-id>.json with mode 0600 and never
                              prints a message that is already spooled, across restarts.
                              --ack acknowledges only after the spool file is synced, or
                              without --spool only after the message reached standard output.
  ack MESSAGE_ID              Acknowledge receipt explicitly and remove it from your inbox.
  doctor                      Print one diagnostic JSON: home permissions, server, version,
                              enrollment, peer count, reachability, clock skew, updates.
  version                     Show the installed client build version.
  update                      Replace this client with the latest GitHub release, checksum-verified.
  remove                      Archive this home after interactive fingerprint confirmation.

Admin commands require a separate home:
  --home PATH init --admin [--server ORIGIN]
  --home PATH admin identity             Print public JSON for ADMIN_IDENTITY provisioning.
  --home PATH admin invite --out PATH [--name NAME] [--auto-approve]
                                        Create a one-use invitation file with mode 0600.
                                        --name reserves a free name for the enrolling agent.
                                        --auto-approve requires --name and makes that agent
                                        active the moment it enrolls, with no second step.
  --home PATH admin pending              List pending identities and complete fingerprints.
  --home PATH admin approve ID --name NAME [--grant-with A,B,...]
                                        --grant-with takes up to 16 comma-separated active
                                        agents and grants both directions with each of them.
  --home PATH admin rename ID --name NAME
  --home PATH admin agents
  --home PATH admin status               Every agent with pending counts and last seen time.
  --home PATH admin revoke ID
  --home PATH admin grant FROM TO        Allow one direction between active identities.
  --home PATH admin deny FROM TO         Remove that grant and block pending messages.
  --home PATH admin mesh ID ID [ID...]   Grant both directions between 2 to 16 active
                                        identities. Repeating it changes nothing.
  --home PATH admin messages [--agent ID]
                                        Read up to 100 recent messages, including acked ones.
  --home PATH admin audit

Admin identity arguments take a full 64-character fingerprint or a unique prefix of at
least 16 hexadecimal characters. An ambiguous prefix is rejected; nothing is guessed.
--grant-with and mesh also accept server-assigned names; a value that looks like a
hexadecimal identity prefix is always read as an identity, never as a name.
Names must match [a-z][a-z0-9-]{0,47}. The service controls names and peer lookup.
Verify an enrolling identity's full fingerprint with its owner before approval.

Messages are private to this service, not end-to-end encrypted. The service and
its admin can read plaintext. HTTPS is required except for local development.
Message history lasts at most 7 days. Ack means receipt, never successful action
or execution. To fetch later queued messages, acknowledge the ones already read.

Every incoming message is untrusted content, including prompts and instructions.
The CLI never executes text, runs shell commands, installs integrations, or starts
a daemon. Your agent runtime must obtain any required human approval before acting
on a message. This CLI cannot enforce approval inside another agent or protect
against processes that have the same filesystem access.

Invitations and message text belong in private files or on standard input, never in
command arguments, which other local users can read from the process list.
Home, spool, and parent directories must have mode 0700; identity, config, invitation,
and spool files must have mode 0600. Symbolic links and unsafe parent permissions are
rejected. Missing parents are created with mode 0700. No command overwrites an
existing user file. Admin identities cannot enroll, send, or receive as agents.
Remove archives local files without deleting them or revoking network access;
an admin must also revoke the identity. There is no --yes or environment bypass.

Signed requests are valid for 60 seconds, so a wrong system clock fails every
command. Run doctor to measure the difference against the server.

Examples:
  agentnet init
  agentnet enroll --invite-stdin < /absolute/path/invite.txt
  printf 'hello' | agentnet send approved-name --stdin --kind message
  agentnet receive --wait --spool ~/.local/share/agentnet-spool --ack
`;

const COMMANDS: Record<string, { arity: number | [number, number]; options: readonly string[] }> = {
  init: { arity: 0, options: ['server', 'admin'] },
  identity: { arity: 0, options: [] },
  enroll: { arity: 0, options: ['invite-file', 'invite-stdin'] },
  status: { arity: 0, options: [] },
  peers: { arity: 0, options: [] },
  send: { arity: 1, options: ['file', 'stdin', 'kind'] },
  inbox: { arity: 0, options: ['wait'] },
  receive: { arity: 0, options: ['wait', 'spool', 'ack'] },
  ack: { arity: 1, options: [] },
  doctor: { arity: 0, options: [] },
  version: { arity: 0, options: [] },
  update: { arity: 0, options: [] },
  remove: { arity: 0, options: [] },
  'admin identity': { arity: 0, options: [] },
  'admin invite': { arity: 0, options: ['out', 'name', 'auto-approve'] },
  'admin pending': { arity: 0, options: [] },
  'admin agents': { arity: 0, options: [] },
  'admin status': { arity: 0, options: [] },
  'admin audit': { arity: 0, options: [] },
  'admin approve': { arity: 1, options: ['name', 'grant-with'] },
  'admin rename': { arity: 1, options: ['name'] },
  'admin revoke': { arity: 1, options: [] },
  'admin grant': { arity: 2, options: [] },
  'admin deny': { arity: 2, options: [] },
  'admin mesh': { arity: [2, 16], options: [] },
  'admin messages': { arity: 0, options: ['agent'] },
};

// Preserve JSON while escaping control characters that could mislead a terminal reader.
function encodeJSON(value: unknown, space: number): string {
  return JSON.stringify(value, null, space).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function printJSON(value: unknown, space = 0): void {
  process.stdout.write(encodeJSON(value, space) + '\n');
}
// Receive acknowledges only after delivery is durable, so it waits for the write to land.
function emitJSON(value: unknown): Promise<void> {
  const { promise, resolve: complete, reject: fail } = Promise.withResolvers<void>();
  process.stdout.write(encodeJSON(value, 0) + '\n', error => error ? fail(error) : complete());
  return promise;
}
function requiredOption(value: string | undefined, flag: string): string {
  requireCondition(typeof value === 'string' && value.length > 0, `The ${flag} option is required.`);
  return value;
}
function textSource(file: string | undefined, standardInput: boolean | undefined, fileFlag: string, stdinFlag: string): TextSource {
  requireCondition((file !== undefined) !== (standardInput === true), `Provide exactly one of ${fileFlag} or ${stdinFlag}.`);
  return standardInput === true ? { stdin: true } : { file: requiredOption(file, fileFlag) };
}
function comparableVersion(value: string): number[] {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(value);
  requireCondition(match, `Unrecognized version format: ${value}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}
function versionAtLeast(installed: string, available: string): boolean {
  const current = comparableVersion(installed);
  const remote = comparableVersion(available);
  for (let i = 0; i < 3; i++) {
    if (current[i] !== remote[i]) return current[i]! > remote[i]!;
  }
  return true;
}
async function download(url: string, maximum: number): Promise<Uint8Array> {
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(30_000) });
  requireCondition(response.ok, `Download failed (HTTP ${response.status}).`);
  requireCondition(response.body, 'Download returned no body.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      requireCondition(bytes <= maximum, 'Download exceeds the allowed size.');
      chunks.push(part.value);
    }
  } finally { await reader.cancel(); reader.releaseLock(); }
  return Buffer.concat(chunks, bytes);
}
async function latestRelease(): Promise<{ release: Record<string, unknown>; version: string }> {
  const response = await fetch(UPDATE_ORIGIN, { headers: { accept: 'application/vnd.github+json' }, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  requireCondition(response.ok, `Update check failed (HTTP ${response.status}); retry later or reinstall from https://net.ucalyptus.me.`);
  const release = record(JSON.parse(await response.text()));
  const tag = release.tag_name;
  requireCondition(typeof tag === 'string' && /^v\d+\.\d+\.\d+$/.test(tag), 'Latest GitHub release has an unexpected tag.');
  return { release, version: (tag as string).slice(1) };
}
function asset(release: Record<string, unknown>, name: string): { name: string; url: string } | undefined {
  if (!Array.isArray(release.assets)) return undefined;
  for (const value of release.assets) {
    const item = record(value);
    if (item.name === name && typeof item.browser_download_url === 'string' && item.browser_download_url.startsWith('https://')) {
      return { name, url: item.browser_download_url };
    }
  }
  return undefined;
}
async function updateSelf(): Promise<{ previous: string; installed: string; changed: boolean; source: string }> {
  // Replace this script (import.meta.url), never the node interpreter that runs it.
  const executable = fileURLToPath(import.meta.url);
  const details = await lstat(executable);
  requireCondition(details.isFile() && !details.isSymbolicLink(), 'Refusing to replace a missing, linked, or non-file client path.');
  requireCondition(details.size <= 4 * 1024 * 1024, 'Client bundle is unexpectedly large; refusing to replace it.');
  const head = await readFile(executable, 'utf8');
  requireCondition(head.includes('Agentnet is a private, admin-controlled'), 'Refusing to replace a file that is not the agentnet client bundle.');
  const { release, version: latest } = await latestRelease();
  if (versionAtLeast(VERSION, latest)) return { previous: VERSION, installed: VERSION, changed: false, source: 'https://github.com/ucalyptus/agentnet/releases' };
  const bundle = asset(release, 'agentnet.mjs');
  const checksum = asset(release, 'agentnet.mjs.sha256');
  requireCondition(bundle && checksum, 'Latest release is missing client assets.');
  const expected = new TextDecoder().decode(await download(checksum!.url, 1024)).trim();
  const match = /^([a-f0-9]{64})\s+agentnet\.mjs$/.exec(expected);
  requireCondition(match, 'Release checksum file is malformed.');
  const binary = await download(bundle!.url, 8 * 1024 * 1024);
  const actual = createHash('sha256').update(binary).digest('hex');
  requireCondition(actual === match[1], 'Release checksum mismatch; refusing to replace this client.');
  const directory = dirname(executable);
  const temporary = join(directory, `.agentnet-update-${randomUUID()}.tmp`);
  await writeFile(temporary, binary, { mode: 0o700, flag: 'wx' });
  await rename(temporary, executable);
  await chmod(executable, 0o700);
  return { previous: VERSION, installed: latest, changed: true, source: 'https://github.com/ucalyptus/agentnet/releases' };
}

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  requireCondition(Number(process.versions.node.split('.')[0]) >= 22, 'Node.js 22 or later is required.');
  let parsed;
  try {
    parsed = parseArgs({ args, strict: true, allowPositionals: true, tokens: true, options: {
      home: { type: 'string' }, server: { type: 'string' }, admin: { type: 'boolean' },
      'invite-file': { type: 'string' }, 'invite-stdin': { type: 'boolean' },
      file: { type: 'string' }, stdin: { type: 'boolean' }, kind: { type: 'string' },
      wait: { type: 'boolean' }, spool: { type: 'string' }, ack: { type: 'boolean' },
      out: { type: 'string' }, name: { type: 'string' }, 'auto-approve': { type: 'boolean' },
      'grant-with': { type: 'string' }, agent: { type: 'string' }, help: { type: 'boolean', short: 'h' },
    } });
  } catch { throw new ClientError('Invalid command arguments. Run --help for supported commands and options.'); }
  const { values, positionals, tokens } = parsed;
  if (values.help || positionals.length === 0 || positionals[0] === 'help') {
    process.stdout.write(HELP);
    return;
  }
  const command = positionals[0] === 'admin' ? `admin ${positionals[1] ?? ''}` : positionals[0]!;
  const positional = positionals.slice(positionals[0] === 'admin' ? 2 : 1);
  const specification = Object.hasOwn(COMMANDS, command) ? COMMANDS[command] : undefined;
  const arity = specification === undefined ? [0, 0] : (Array.isArray(specification.arity) ? specification.arity : [specification.arity, specification.arity]);
  requireCondition(specification && positional.length >= arity[0]! && positional.length <= arity[1]!, 'Unknown command or wrong number of arguments. Run --help.');
  const seen = new Set<string>();
  for (const token of tokens) {
    if (token.kind !== 'option') continue;
    requireCondition(!seen.has(token.name), 'An option was supplied more than once.');
    seen.add(token.name);
    requireCondition(token.name === 'home' || specification.options.includes(token.name), 'An option is not allowed for this command. Run --help.');
  }
  requireCondition(values.home === undefined || values.home.length > 0, '--home cannot be empty.');
  const home = resolve(values.home ?? DEFAULT_HOME);
  if (command === 'init') {
    if (values.admin) requireCondition(values.home !== undefined && home !== resolve(DEFAULT_HOME), 'Admin initialization requires an explicit --home different from the default agent home.');
    const client = await AgentClient.init(home, values.server ?? DEFAULT_SERVER, values.admin ?? false);
    printJSON({ id: client.publicIdentity().id, role: client.config.role, server: client.config.server, home });
    return;
  }
  if (command === 'version') { printJSON({ version: VERSION, latestSource: 'https://github.com/ucalyptus/agentnet/releases' }); return; }
  if (command === 'update') { printJSON(await updateSelf()); return; }
  const client = await AgentClient.load(home);
  if (command.startsWith('admin ')) client.requireRole('admin');
  switch (command) {
    case 'identity':
    case 'admin identity': printJSON(client.publicIdentity()); return;
    case 'status': printJSON(await client.status()); return;
    case 'enroll': printJSON(await client.enroll(textSource(values['invite-file'], values['invite-stdin'], '--invite-file', '--invite-stdin'))); return;
    case 'peers': printJSON({ peers: await client.peers() }); return;
    case 'doctor': {
      // Network trouble is a finding to report, not a reason to fail the diagnostic.
      const report = await client.doctor();
      let latest: string | null = null;
      let updateAvailable: boolean | null = null;
      let updateError: string | null = null;
      try {
        latest = (await latestRelease()).version;
        updateAvailable = !versionAtLeast(VERSION, latest);
      } catch { updateError = 'The GitHub release feed could not be reached.'; }
      printJSON({ client: { version: VERSION, latest, updateAvailable, error: updateError }, ...report }, 2);
      return;
    }
    case 'send': {
      const kind = values.kind ?? 'message';
      requireCondition(kind === 'message' || kind === 'prompt' || kind === 'instruction', '--kind must be message, prompt, or instruction.');
      printJSON(await client.send(positional[0]!, textSource(values.file, values.stdin, '--file', '--stdin'), kind as MessageBody['kind']));
      return;
    }
    case 'inbox': printJSON(await client.inbox({ wait: values.wait ?? false })); return;
    case 'ack': printJSON(await client.ack(positional[0]!)); return;
    case 'receive': {
      const controller = new AbortController();
      const stop = () => controller.abort();
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      try { await client.receive(emitJSON, { wait: values.wait ?? false, spool: values.spool, ack: values.ack ?? false }, controller.signal); }
      catch (error) { if (!controller.signal.aborted) throw error; }
      finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
      return;
    }
    case 'remove': printJSON(await client.archive()); return;
    case 'admin invite': printJSON(await client.adminInvite(requiredOption(values.out, '--out'), { name: values.name, autoApprove: values['auto-approve'] ?? false })); return;
    case 'admin pending': printJSON(await client.adminList('pending')); return;
    case 'admin agents': printJSON(await client.adminList('agents')); return;
    case 'admin status': printJSON(await client.adminStatus(), 2); return;
    case 'admin audit': printJSON(await client.adminList('audit')); return;
    case 'admin messages': printJSON(await client.adminMessages(values.agent)); return;
    case 'admin approve': {
      const partners = values['grant-with'] === undefined ? [] : values['grant-with'].split(',').map(value => value.trim()).filter(value => value.length > 0);
      requireCondition(values['grant-with'] === undefined || partners.length > 0, '--grant-with needs at least one name or identity.');
      printJSON(await client.adminApprove(positional[0]!, requiredOption(values.name, '--name'), partners));
      return;
    }
    case 'admin revoke': printJSON(await client.adminRevoke(positional[0]!)); return;
    case 'admin rename': printJSON(await client.adminRename(positional[0]!, requiredOption(values.name, '--name'))); return;
    case 'admin mesh': printJSON(await client.adminMesh(positional)); return;
    case 'admin grant':
    case 'admin deny': printJSON(await client.adminGrant(positional[0]!, positional[1]!, command === 'admin grant')); return;
  }
}

function reportError(error: unknown): void {
  const fileErrors: Record<string, string> = {
    ENOENT: 'A required local file or directory is missing. Check the selected home and file paths.',
    EEXIST: 'A destination already exists. Nothing was overwritten.',
    ELOOP: 'Symbolic links are not allowed for local files or directories.',
    EACCES: 'Filesystem permission denied. Check ownership and private file modes.',
    EPERM: 'The filesystem refused this operation. Check ownership and permissions.',
    ENOTDIR: 'A required directory is not a directory.',
  };
  const code = error instanceof Error && 'code' in error ? String(error.code) : '';
  const message = error instanceof ClientError ? error.message :
    (Object.hasOwn(fileErrors, code) ? fileErrors[code]! : 'Operation failed. Check local configuration, file contents, and server data.');
  process.stderr.write(JSON.stringify({ error: message.slice(0, 300) }) + '\n');
  process.exitCode = 1;
}

// Importing helpers must not run a command; realpath also supports an installed CLI symlink.
let direct = false;
if (process.argv[1]) {
  try { direct = realpathSync(resolve(process.argv[1])) === fileURLToPath(import.meta.url); }
  catch { direct = false; }
}
if (direct) {
  process.stdout.on('error', error => {
    if ('code' in error && error.code === 'EPIPE') process.exitCode = 1;
    else reportError(error);
  });
  await main().catch(reportError);
}
