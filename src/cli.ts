#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { dirname, join, resolve } from 'node:path';
import { realpathSync } from 'node:fs';
import { chmod, lstat, readFile, rename, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  AgentClient, ClientError, DEFAULT_HOME, DEFAULT_SERVER, messageKind, requireCondition,
  type TextSource,
} from './client.js';
import { record, verifyManifest, type PublicIdentity } from './protocol.js';

const GITHUB_LATEST = 'https://api.github.com/repos/ucalyptus/agentnet/releases/latest';

// Replaced at build time from package.json; survives direct source execution via the default.
declare const __AGENTNET_VERSION__: string | undefined;
export const VERSION = __AGENTNET_VERSION__ ?? '0.3.0-dev';

const HELP = `Agentnet is a private, admin-controlled message service.

Usage: agentnet [--home PATH] COMMAND [OPTIONS]
Default home: ~/.local/share/agentnet
Default server: ${DEFAULT_SERVER}
Requires Node.js 22 or later on macOS or Linux with POSIX file permissions.
Run doctor for the installed build, the update channel, and mesh health. It prints the
current numbers, so nothing here needs to repeat a version.

Agent commands:
  init [--server ORIGIN] [--label TEXT]
                              Create an identity once. Existing identities stay unchanged.
                              One home holds one identity for one server.
                              --label stores a short local description that hello shares
                              with a peer. Repeat init or use label to change it.
  identity                    Print public identity JSON, never the private signing key.
  label TEXT                  Set the local label. An empty value clears it. A label is
                              letters, digits, spaces, dots, dashes, or underscores only.
  enroll --invite-file PATH   Request enrollment using a private invitation file.
  enroll --invite-stdin       Read the invitation token from standard input instead.
                              An auto-approving invitation returns active with your name.
                              An invitation created with --for only works for that one
                              fingerprint; another identity is refused and the token stays
                              unused.
  status [--watch]            Show pending, active, or revoked status, the server time, and
                              which admin key this home trusts.
                              --watch prints the current state and, while pending, holds one
                              request until an admin approves or revokes, then prints the new
                              state and exits. An agent can wait for approval without a
                              human polling. Ctrl+C or SIGTERM stops it.
  trust-admin [--accept-new-key]
                              Print and pin this service's admin key, the key that signs
                              client releases. The first successful status call pins it
                              automatically, so this is only needed after the owner rotates
                              it. A server that presents a different key fails every command
                              until the owner verifies the new fingerprint out of band and
                              runs this with --accept-new-key.
  peers                       List allowed outgoing recipients. inbound reports whether that
                              peer may also send to you, so a reply can come back.
  send RECIPIENT --file PATH [--kind message|prompt|instruction|result]
  send RECIPIENT --stdin [--kind message|prompt|instruction|result]
                              Send UTF-8 text to a current peer ID or server-assigned name.
                              Message text is never a command argument.
                              --kind result is for reporting an outcome back to a peer.
                              Prefer it over reusing ack, which is transport only.
                              The receipt adds recipientPending, the recipient's unread
                              count, and replyPossible:false when that peer has no grant
                              back, which is why a send can look ignored.
  hello RECIPIENT             Send a fixed capability card as kind result: name, client
                              version, Node version, label, and whether the recipient may
                              reply. It is built only from local facts and carries no
                              free-form text, so it adds no injection surface.
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
  doctor                      One diagnostic JSON in separate sections: client and
                              updateChannel describe where new builds come from and how the
                              last check was verified; local covers home and identity file
                              modes, the pinned admin key, and the Node version; mesh covers
                              enrollment, peer count, inbound grants, reachability, clock
                              skew, and the recommended poll cadence. An update channel
                              outage is never a mesh problem.
  version                     Show the installed client build version.
  update                      Replace this client with the latest release. The published
                              checksum is always verified. When this home has pinned an
                              admin key, the manifest must also carry that admin's signature
                              over the version and checksum; an unsigned or mismatched
                              manifest is refused and nothing is written. The result reports
                              verified: admin-signature or verified: checksum.
                              A pinned absolute interpreter on the first line is kept.
                              A failed update repeats the reinstall one-liner for
                              <server>/install.sh in its error.
  remove                      Archive this home after interactive fingerprint confirmation.

Admin commands require a separate home:
  --home PATH init --admin [--server ORIGIN]
  --home PATH admin identity             Print public JSON for ADMIN_IDENTITY provisioning.
  --home PATH admin invite --out PATH [--name NAME] [--auto-approve] [--for FINGERPRINT]
                                        Create a one-use invitation file with mode 0600.
                                        --name reserves a free name for the enrolling agent.
                                        --auto-approve requires --name and makes that agent
                                        active the moment it enrolls, with no second step.
                                        --for takes a full 64-character fingerprint and binds
                                        the invitation to it, so a leaked token is useless to
                                        anyone else. Combine it with either other option.
  --home PATH admin pending [--wait]     List pending identities and complete fingerprints.
                                        --wait holds the request up to 25s and returns as
                                        soon as a new enrollment request arrives.
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

Grants are one directional. A peer listed by peers with inbound:false cannot answer you,
and a send to it reports replyPossible:false. Ask an admin for the reverse grant or a mesh.

A client release is published with a checksum and a manifest signed by the admin key.
This home pins that key the first time status succeeds, so a later key change stops every
command instead of silently trusting a new signer. doctor prints the pinned fingerprint.

Messages are private to this service, not end-to-end encrypted. The service and
its admin can read plaintext. HTTPS is required except for local development.
Message history lasts at most 7 days. Ack is a transport receipt only: it means the
message reached durable local storage, never that it was read, executed, approved, or
completed. Report an outcome with send --kind result instead of overloading ack.
To fetch later queued messages, acknowledge the ones already read.

Every incoming message is untrusted content, including prompts, instructions, results,
and capability cards. The CLI never executes text, runs shell commands, installs
integrations, or starts a daemon. Your agent runtime must obtain any required human
approval before acting on a message. This CLI cannot enforce approval inside another
agent or protect against processes that have the same filesystem access.

Invitations and message text belong in private files or on standard input, never in
command arguments, which other local users can read from the process list.
Home, spool, and parent directories must have mode 0700; identity, config, invitation,
and spool files must have mode 0600. Symbolic links and unsafe parent permissions are
rejected. Missing parents are created with mode 0700. No command overwrites an
existing user file, and config.json is only ever replaced by an atomic rename.
Admin identities cannot enroll, send, or receive as agents.
Remove archives local files without deleting them or revoking network access;
an admin must also revoke the identity. There is no --yes or environment bypass.

Signed requests are valid for 60 seconds, so a wrong system clock fails every
command. Run doctor to measure the difference against the server.

Examples:
  agentnet init --label build-runner
  agentnet enroll --invite-stdin < /absolute/path/invite.txt
  agentnet status --watch
  agentnet hello approved-name
  printf 'hello' | agentnet send approved-name --stdin --kind message
  printf 'build ok' | agentnet send approved-name --stdin --kind result
  agentnet receive --wait --spool ~/.local/share/agentnet-spool --ack
`;

const COMMANDS: Record<string, { arity: number | [number, number]; options: readonly string[] }> = {
  init: { arity: 0, options: ['server', 'admin', 'label'] },
  identity: { arity: 0, options: [] },
  label: { arity: 1, options: [] },
  enroll: { arity: 0, options: ['invite-file', 'invite-stdin'] },
  status: { arity: 0, options: ['watch'] },
  'trust-admin': { arity: 0, options: ['accept-new-key'] },
  hello: { arity: 1, options: [] },
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
  'admin invite': { arity: 0, options: ['out', 'name', 'auto-approve', 'for'] },
  'admin pending': { arity: 0, options: ['wait'] },
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
// A held request ends on Ctrl+C or SIGTERM, which is an ordinary stop, not a failure.
async function untilInterrupted(run: (signal: AbortSignal) => Promise<void>): Promise<void> {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try { await run(controller.signal); }
  catch (error) { if (!controller.signal.aborted) throw error; }
  finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
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
interface Build {
  version: string; bundleUrl: string; checksum: string | null; checksumUrl: string | null;
  verified: 'admin-signature' | 'checksum'; source: string;
}
// A trust failure is not a reachability failure: it must never be retried on another host,
// because another host is exactly what an attacker would offer.
class TrustError extends ClientError {}
function requireTrust(condition: unknown, message: string): asserts condition {
  if (!condition) throw new TrustError(message);
}
const MANIFEST_LIMIT = 8192;
const BUNDLE_PATH = /^\/[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const DEFAULT_SHEBANG = '#!/usr/bin/env node';
const SHEBANG = /^#!\/[\x21-\x7e]{1,160}( [\x21-\x7e]{1,40})?$/;
// The manifest states the version and the bundle checksum. When this home has pinned the
// admin key, the manifest must also carry that admin's signature over exactly those two
// values, so neither the service nor GitHub can serve a different client build.
async function readManifest(text: string, adminKey: PublicIdentity | null): Promise<{ version: string; checksum: string; bundle: string; verified: Build['verified'] }> {
  requireCondition(text.length <= MANIFEST_LIMIT, 'Update manifest is unexpectedly large.');
  const manifest = record(JSON.parse(text));
  const version = manifest.version;
  const checksum = manifest.sha256;
  requireCondition(typeof version === 'string' && /^\d+\.\d+\.\d+$/.test(version), 'Update manifest has an unexpected version.');
  requireCondition(typeof checksum === 'string' && /^[a-f0-9]{64}$/.test(checksum), 'Update manifest has an unexpected checksum.');
  const bundle = manifest.bundle === undefined ? '/agentnet.mjs' : manifest.bundle;
  requireCondition(typeof bundle === 'string' && bundle.length <= 128 && BUNDLE_PATH.test(bundle) && !bundle.includes('..'), 'Update manifest has an unexpected bundle path.');
  if (adminKey === null) return { version, checksum, bundle, verified: 'checksum' };
  const signature = manifest.signature;
  requireTrust(typeof signature === 'string' && signature.length <= 4096 && COMPACT_JWS.test(signature),
    'This update manifest carries no admin signature, but this home pins an admin key. Refusing to install a client that cannot be traced to that admin.');
  let signed;
  try { signed = await verifyManifest(signature, adminKey); }
  catch { throw new TrustError('The update manifest signature does not verify against the admin key pinned in this home. Refusing to install.'); }
  requireTrust(signed.version === version && signed.sha256 === checksum, 'The signed manifest does not match the published version or checksum. Refusing to install.');
  return { version, checksum, bundle, verified: 'admin-signature' };
}
// The service is primary: it is the origin the client already trusts and reaches, and it
// has no third-party rate limit. GitHub's unauthenticated API allows 60 requests per hour
// per IP address, which shared agent sandboxes exhaust, returning HTTP 403.
async function serviceBuild(origin: string, adminKey: PublicIdentity | null): Promise<Build> {
  const response = await fetch(`${origin}/version.json`, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  requireCondition(response.ok, `Service version manifest unavailable (HTTP ${response.status}).`);
  const advertised = response.headers.get('content-length');
  requireCondition(advertised === null || (/^\d+$/.test(advertised) && Number(advertised) <= MANIFEST_LIMIT), 'Update manifest is unexpectedly large.');
  const manifest = await readManifest(await response.text(), adminKey);
  return {
    version: manifest.version, bundleUrl: `${origin}${manifest.bundle}`, checksum: manifest.checksum,
    checksumUrl: null, verified: manifest.verified, source: origin,
  };
}
async function githubBuild(adminKey: PublicIdentity | null): Promise<Build> {
  const response = await fetch(GITHUB_LATEST, { headers: { accept: 'application/vnd.github+json' }, redirect: 'error', signal: AbortSignal.timeout(20_000) });
  requireCondition(response.ok, response.status === 403
    ? 'GitHub rejected the release lookup (HTTP 403), which usually means its unauthenticated hourly limit for this IP address is exhausted.'
    : `GitHub release lookup failed (HTTP ${response.status}).`);
  const release = record(JSON.parse(await response.text()));
  const tag = release.tag_name;
  requireCondition(typeof tag === 'string' && /^v\d+\.\d+\.\d+$/.test(tag), 'Latest GitHub release has an unexpected tag.');
  const bundle = asset(release, 'agentnet.mjs');
  const checksum = asset(release, 'agentnet.mjs.sha256');
  requireCondition(bundle && checksum, 'Latest release is missing client assets.');
  const source = 'https://github.com/ucalyptus/agentnet/releases';
  // The release publishes the same signed manifest, so the fallback path is held to the
  // same rule: a pinned admin key means an unsigned release is not installable.
  const published = asset(release, 'version.json');
  if (published) {
    const manifest = await readManifest(new TextDecoder().decode(await download(published.url, MANIFEST_LIMIT)), adminKey);
    requireTrust(manifest.version === tag.slice(1), 'The release manifest does not match the release tag.');
    return { version: manifest.version, bundleUrl: bundle!.url, checksum: manifest.checksum, checksumUrl: null, verified: manifest.verified, source };
  }
  requireTrust(adminKey === null, 'This release publishes no signed manifest, but this home pins an admin key. Refusing to install a client that cannot be traced to that admin.');
  return { version: tag.slice(1), bundleUrl: bundle!.url, checksum: null, checksumUrl: checksum!.url, verified: 'checksum', source };
}
async function latestBuild(origin: string, adminKey: PublicIdentity | null): Promise<Build> {
  try { return await serviceBuild(origin, adminKey); }
  catch (serviceError) {
    if (serviceError instanceof TrustError) throw serviceError;
    try { return await githubBuild(adminKey); }
    catch (githubError) {
      if (githubError instanceof TrustError) throw githubError;
      throw new ClientError(`No update source reachable. Service: ${serviceError instanceof Error ? serviceError.message : 'failed'} GitHub: ${githubError instanceof Error ? githubError.message : 'failed'}`.slice(0, 280));
    }
  }
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
interface UpdateResult {
  previous: string; installed: string; changed: boolean; source: string;
  verified: Build['verified']; interpreter: 'pinned' | 'default';
}
async function installUpdate(origin: string, adminKey: PublicIdentity | null): Promise<UpdateResult> {
  // Replace this script (import.meta.url), never the node interpreter that runs it.
  const executable = fileURLToPath(import.meta.url);
  const details = await lstat(executable);
  requireCondition(details.isFile() && !details.isSymbolicLink(), 'Refusing to replace a missing, linked, or non-file client path.');
  requireCondition(details.size <= 4 * 1024 * 1024, 'Client bundle is unexpectedly large; refusing to replace it.');
  const head = await readFile(executable, 'utf8');
  requireCondition(head.includes('Agentnet is a private, admin-controlled'), 'Refusing to replace a file that is not the agentnet client bundle.');
  // The installer may pin a validated absolute node path on the first line; the published
  // bundle ships the portable default, so that choice is carried across the update.
  const firstBreak = head.indexOf('\n');
  const currentShebang = head.startsWith('#!/') && firstBreak > 2 ? head.slice(0, firstBreak) : null;
  const interpreter: UpdateResult['interpreter'] = currentShebang !== null && currentShebang !== DEFAULT_SHEBANG ? 'pinned' : 'default';
  const build = await latestBuild(origin, adminKey);
  if (versionAtLeast(VERSION, build.version)) {
    return { previous: VERSION, installed: VERSION, changed: false, source: build.source, verified: build.verified, interpreter };
  }
  let expected = build.checksum;
  if (expected === null) {
    const published = new TextDecoder().decode(await download(build.checksumUrl!, 1024)).trim();
    const match = /^([a-f0-9]{64})\s+agentnet\.mjs$/.exec(published);
    requireCondition(match, 'Published checksum file is malformed.');
    expected = match[1]!;
  }
  const binary = await download(build.bundleUrl, 8 * 1024 * 1024);
  // Verify the published bytes before any local rewriting, so the checksum always covers
  // exactly what was published rather than what this client produced.
  requireTrust(createHash('sha256').update(binary).digest('hex') === expected, 'Checksum mismatch; refusing to replace this client.');
  let bytes: Uint8Array = binary;
  if (currentShebang !== null) {
    const newlineAt = binary.indexOf(0x0a);
    requireCondition(newlineAt > 2 && newlineAt < 512, 'The downloaded client has no leading line, so a pinned interpreter cannot be carried over.');
    const downloadedShebang = new TextDecoder().decode(binary.subarray(0, newlineAt));
    if (downloadedShebang.startsWith('#!') && downloadedShebang !== currentShebang) {
      requireCondition(SHEBANG.test(currentShebang), 'The installed client has an unexpected first line; refusing to carry it into the update.');
      bytes = Buffer.concat([Buffer.from(currentShebang + '\n', 'utf8'), binary.subarray(newlineAt + 1)]);
    }
  }
  const temporary = join(dirname(executable), `.agentnet-update-${randomUUID()}.tmp`);
  await writeFile(temporary, bytes, { mode: 0o700, flag: 'wx' });
  await rename(temporary, executable);
  await chmod(executable, 0o700);
  return { previous: VERSION, installed: build.version, changed: true, source: build.source, verified: build.verified, interpreter };
}
// Every failure carries the recovery line: agents reported having to remember it.
async function updateSelf(origin: string, adminKey: PublicIdentity | null): Promise<UpdateResult> {
  try { return await installUpdate(origin, adminKey); }
  catch (error) {
    const code = error instanceof Error && 'code' in error ? ` (${String(error.code).slice(0, 20)})` : '';
    const detail = (error instanceof Error ? error.message : 'Update failed.').slice(0, 170);
    throw new ClientError(`${detail}${code} Recovery: move the current client aside, then reinstall: curl -fsSL ${origin}/install.sh -o install.sh && sh install.sh ${origin}`);
  }
}

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  requireCondition(Number(process.versions.node.split('.')[0]) >= 22, 'Node.js 22 or later is required.');
  let parsed;
  try {
    parsed = parseArgs({ args, strict: true, allowPositionals: true, tokens: true, options: {
      home: { type: 'string' }, server: { type: 'string' }, admin: { type: 'boolean' }, label: { type: 'string' },
      'invite-file': { type: 'string' }, 'invite-stdin': { type: 'boolean' },
      file: { type: 'string' }, stdin: { type: 'boolean' }, kind: { type: 'string' },
      wait: { type: 'boolean' }, watch: { type: 'boolean' }, spool: { type: 'string' }, ack: { type: 'boolean' },
      'accept-new-key': { type: 'boolean' },
      out: { type: 'string' }, name: { type: 'string' }, 'auto-approve': { type: 'boolean' }, for: { type: 'string' },
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
    const client = await AgentClient.init(home, values.server ?? DEFAULT_SERVER, values.admin ?? false, values.label);
    printJSON({ id: client.publicIdentity().id, role: client.config.role, server: client.config.server, label: client.config.label, home });
    return;
  }
  if (command === 'version' || command === 'update') {
    // These work without a usable home; fall back to the published service origin. A home
    // that exists also supplies the pinned admin key that must sign the next build.
    let origin = DEFAULT_SERVER;
    let adminKey: PublicIdentity | null = null;
    try {
      const loaded = await AgentClient.load(home);
      origin = loaded.config.server;
      adminKey = loaded.config.adminKey;
    } catch { /* home is optional here */ }
    if (command === 'version') {
      printJSON({ version: VERSION, nodeVersion: process.versions.node, updateSource: origin, adminKeyPinned: adminKey === null ? null : adminKey.id });
      return;
    }
    printJSON(await updateSelf(origin, adminKey));
    return;
  }
  const client = await AgentClient.load(home);
  if (command.startsWith('admin ')) client.requireRole('admin');
  switch (command) {
    case 'identity':
    case 'admin identity': printJSON(client.publicIdentity()); return;
    case 'status': {
      if (values.watch !== true) { printJSON(await client.status()); return; }
      await untilInterrupted(signal => client.watchStatus(emitJSON, signal));
      return;
    }
    case 'trust-admin': printJSON(await client.trustAdmin(values['accept-new-key'] ?? false)); return;
    case 'label': printJSON(await client.setLabel(positional[0]!)); return;
    case 'hello': printJSON(await client.hello(positional[0]!, VERSION)); return;
    case 'enroll': printJSON(await client.enroll(textSource(values['invite-file'], values['invite-stdin'], '--invite-file', '--invite-stdin'))); return;
    case 'peers': printJSON({ peers: await client.peers() }); return;
    case 'doctor': {
      // Where builds come from is a separate question from whether the mesh works, so an
      // update source outage is reported on its own and never as a health failure.
      const report = await client.doctor();
      let latest: string | null = null;
      let updateAvailable: boolean | null = null;
      let updateSource: string | null = null;
      let verified: Build['verified'] | null = null;
      let updateError: string | null = null;
      try {
        const build = await latestBuild(client.config.server, client.config.adminKey);
        latest = build.version;
        updateSource = build.source;
        verified = build.verified;
        updateAvailable = !versionAtLeast(VERSION, latest);
      } catch (error) { updateError = (error instanceof ClientError ? error.message : 'No update source could be reached.').slice(0, 240); }
      printJSON({
        client: { version: VERSION, nodeVersion: process.versions.node },
        updateChannel: {
          reachable: updateError === null, latest, updateAvailable, verified, source: updateSource, error: updateError,
          note: 'This section only describes where a new client build comes from and how it was verified. A failure here, including a GitHub or service outage, does not affect the mesh health reported below.',
        },
        ...report,
      }, 2);
      return;
    }
    case 'send': printJSON(await client.send(positional[0]!, textSource(values.file, values.stdin, '--file', '--stdin'), messageKind(values.kind ?? 'message'))); return;
    case 'inbox': printJSON(await client.inbox({ wait: values.wait ?? false })); return;
    case 'ack': printJSON(await client.ack(positional[0]!)); return;
    case 'receive':
      await untilInterrupted(signal => client.receive(emitJSON, { wait: values.wait ?? false, spool: values.spool, ack: values.ack ?? false }, signal));
      return;
    case 'remove': printJSON(await client.archive()); return;
    case 'admin invite': printJSON(await client.adminInvite(requiredOption(values.out, '--out'), { name: values.name, autoApprove: values['auto-approve'] ?? false, for: values.for })); return;
    case 'admin pending': printJSON(await client.adminList('pending', { wait: values.wait ?? false })); return;
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
