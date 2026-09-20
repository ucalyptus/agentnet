import { constants, type Stats } from 'node:fs';
import { open, lstat, mkdir, readdir, rename, link, unlink } from 'node:fs/promises';
import { dirname, join, parse, resolve } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { setTimeout as delay } from 'node:timers/promises';
import {
  ID_PATTERN, UUID_PATTERN, MAX_TEXT_BYTES, MAX_REQUEST_BYTES,
  generateIdentity, validatePublicIdentity, serverURL, signRequest, verifyRequest,
  createMessage, validateMessage, record,
  type PrivateIdentity, type PublicIdentity, type Peer, type InboxItem, type MessageBody, type Message,
} from './protocol.js';

const NAME_PATTERN = /^[a-z][a-z0-9-]{0,47}$/;
// Admin commands accept a full fingerprint or a long unique prefix; the server resolves it.
const REFERENCE_PATTERN = /^[a-f0-9]{16,64}$/;
const INVITE_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;
// A label is local metadata that hello shares with a peer, so it stays short and plain:
// no quotes, newlines, or punctuation that could read as prose or markup on the far side.
const LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const VERSION_PATTERN = /^[0-9][0-9A-Za-z.+-]{0,31}$/;
const KINDS: Record<MessageBody['kind'], true> = { message: true, prompt: true, instruction: true, result: true };
// Matches the service identity capacity; a smaller cap would reject a large but legal mesh.
const LIST_LIMIT = 10_000;
const RESPONSE_LIMIT = 4 * 1024 * 1024;
const REQUEST_TIMEOUT = 15_000;
// The server holds a waiting inbox request for up to 25 seconds before answering.
const WAIT_TIMEOUT = 35_000;
// Floor between polls that returned nothing new, so a held inbox never becomes a busy loop.
const IDLE_DELAY = 5_000;
const CLOCK_WARNING = 10_000;
const decoder = new TextDecoder('utf-8', { fatal: true });
export const DEFAULT_HOME = join(homedir(), '.local', 'share', 'agentnet');
export const DEFAULT_SERVER = 'https://net.ucalyptus.me';
export class ClientError extends Error {}
export function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new ClientError(message);
}
function isCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}
const FILE_ERROR_TEXT: Record<string, string> = {
  ENOENT: 'A required local file or directory is missing.',
  EEXIST: 'A destination already exists. Nothing was overwritten.',
  ELOOP: 'Symbolic links are not allowed for local files or directories.',
  EACCES: 'Filesystem permission denied. Check ownership and private file modes.',
  EPERM: 'The filesystem refused this operation. Check ownership and permissions.',
  ENOTDIR: 'A required directory is not a directory.',
};
// Local filesystem failures carry the offending path; report it so the user can fix it.
// Paths are not secret; file contents are, and they are never included.
export function describeFileError(error: unknown): string | null {
  if (!(error instanceof Error) || !('path' in error) || typeof error.path !== 'string' || error.path === '') return null;
  const code = 'code' in error ? error.code : undefined;
  if (typeof code !== 'string') return null;
  const text = FILE_ERROR_TEXT[code];
  return text === undefined ? null : `${text} Path: ${error.path}`;
}
function uid(): number {
  requireCondition(typeof process.getuid === 'function', 'A POSIX filesystem with owner permissions is required.');
  return process.getuid();
}
function checkDirectory(stat: Stats, privateDirectory: boolean, path: string): void {
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(), `A directory is missing or is a symbolic link. Path: ${path}`);
  if (privateDirectory) {
    requireCondition(stat.uid === uid() && (stat.mode & 0o7777) === 0o700, `Agent directories must be owned by you and have mode 0700. Path: ${path}`);
  } else {
    const stickyRoot = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    requireCondition((stat.uid === uid() || stat.uid === 0) && ((stat.mode & 0o022) === 0 || stickyRoot), `A parent directory has unsafe ownership or write permissions. Path: ${path}`);
  }
}
async function inspect(path: string): Promise<Stats | undefined> {
  try { return await lstat(path); } catch (error) { if (isCode(error, 'ENOENT')) return undefined; throw error; }
}
async function checkParents(path: string, create = false): Promise<void> {
  const parent = dirname(resolve(path));
  const root = parse(parent).root;
  checkDirectory(await lstat(root), false, root);
  let current = root;
  for (const part of parent.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part);
    let stat = await inspect(current);
    if (!stat && create) {
      try { await mkdir(current, { mode: 0o700 }); } catch (error) { if (!isCode(error, 'EEXIST')) throw error; }
      stat = await lstat(current);
    }
    requireCondition(stat, `A parent directory does not exist. Path: ${current}`);
    checkDirectory(stat, false, current);
  }
}
async function privateDirectory(path: string, create = false): Promise<void> {
  await checkParents(path, create);
  if (create) {
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (!isCode(error, 'EEXIST')) throw error; }
  }
  checkDirectory(await lstat(path), true, path);
}
export async function readFileSafely(path: string, maximum: number, secret = true): Promise<string> {
  await checkParents(path);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    requireCondition(stat.isFile() && stat.nlink === 1, 'Expected a regular file without hard links.');
    if (secret) requireCondition(stat.uid === uid() && (stat.mode & 0o7777) === 0o600, 'Private files must be owned by you and have mode 0600.');
    requireCondition(stat.size <= maximum, 'File exceeds the allowed size.');
    const bytes = Buffer.alloc(maximum + 1);
    let count = 0;
    while (count < bytes.length) {
      const result = await handle.read(bytes, count, bytes.length - count, null);
      if (result.bytesRead === 0) break;
      count += result.bytesRead;
    }
    requireCondition(count <= maximum, 'File exceeds the allowed size.');
    return decoder.decode(bytes.subarray(0, count));
  } finally { await handle.close(); }
}
// Standard input keeps secrets out of argv and out of temporary files nobody deletes.
async function readStandardInput(maximum: number): Promise<string> {
  requireCondition(!process.stdin.isTTY, 'Standard input is a terminal. Pipe the content in or use the file option.');
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string, 'utf8');
    bytes += part.byteLength;
    requireCondition(bytes <= maximum, 'Standard input exceeds the allowed size.');
    chunks.push(part);
  }
  return decoder.decode(Buffer.concat(chunks, bytes));
}
export type TextSource = { file: string } | { stdin: true };
async function readSource(source: TextSource, maximum: number, secret: boolean): Promise<string> {
  return 'stdin' in source ? readStandardInput(maximum) : readFileSafely(resolve(source.file), maximum, secret);
}
async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
// Write and sync a complete file beside its destination, then publish it in one step.
async function writeTemporary(path: string, text: string): Promise<string> {
  await checkParents(path);
  const temporary = join(dirname(path), `.agentnet-${randomUUID()}.tmp`);
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(text, 'utf8');
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(temporary);
    throw error;
  }
  await handle.close();
  return temporary;
}
// Publish a complete synced file without replacing an existing path.
async function writeExclusive(path: string, text: string): Promise<void> {
  const temporary = await writeTemporary(path, text);
  try { await link(temporary, path); }
  finally { await unlink(temporary); }
  await syncDirectory(dirname(path));
}
// Replace a file this home owns. A reader sees either the old or the new content, never
// a partial one, and the rename never follows a symbolic link planted at the destination.
async function writeReplace(path: string, text: string): Promise<void> {
  const existing = await inspect(path);
  requireCondition(!existing || (existing.isFile() && !existing.isSymbolicLink() && existing.nlink === 1 && existing.uid === uid()), 'Refusing to replace a file that is not a private regular file you own.');
  const temporary = await writeTemporary(path, text);
  try { await rename(temporary, path); }
  catch (error) { await unlink(temporary); throw error; }
  await syncDirectory(dirname(path));
}
// A spool file is both the local copy and the durable cursor: an existing name means
// the message was already delivered to this spool and must never be printed again.
async function spoolMessage(directory: string, item: InboxItem & { untrusted: true }): Promise<boolean> {
  try {
    await writeExclusive(join(directory, `${messageID(item.message.id)}.json`), JSON.stringify({ ...item, transportOnly: true }) + '\n');
    return true;
  } catch (error) {
    if (isCode(error, 'EEXIST')) return false;
    throw error;
  }
}
function name(value: unknown): string {
  requireCondition(typeof value === 'string' && NAME_PATTERN.test(value), 'Invalid agent name.');
  return value;
}
function label(value: unknown): string {
  requireCondition(typeof value === 'string' && LABEL_PATTERN.test(value), 'A label must be 1 to 64 characters of letters, digits, spaces, dots, dashes, or underscores.');
  return value;
}
export function messageKind(value: unknown): MessageBody['kind'] {
  requireCondition(typeof value === 'string' && Object.hasOwn(KINDS, value), 'A message kind must be message, prompt, instruction, or result.');
  return value as MessageBody['kind'];
}
export function identityID(value: unknown): string {
  requireCondition(typeof value === 'string' && ID_PATTERN.test(value), 'Use the complete 64-character identity fingerprint.');
  return value;
}
export function identityReference(value: unknown): string {
  const ungrouped = ungroupIdentity(value);
  requireCondition(REFERENCE_PATTERN.test(ungrouped), 'Use a complete 64-character identity fingerprint or a unique prefix of at least 16 hexadecimal characters.');
  return ungrouped;
}
// Identity arguments may be pasted from a chat screenshot in grouped form (spaces,
// tabs, colons, or dashes between groups); strip that grouping before validation.
// Only a valid hexadecimal reference qualifies as grouped: an agent name may contain
// dashes, so a dash-stripped string that is not all hex is left untouched.
function ungroupIdentity(value: unknown): string {
  if (typeof value !== 'string') return '';
  const stripped = value.replace(/[\s:-]/g, '');
  return REFERENCE_PATTERN.test(stripped) ? stripped : value;
}
// A screenshot may show a fingerprint grouped in fours; produce the same form for a
// human to compare side by side.
export function groupedFingerprint(id: string): string {
  return id.replace(/[0-9a-f]{4}(?=[0-9a-f])/g, '$& ');
}
function resolvedID(value: unknown, reference: string): string {
  const id = identityID(value);
  requireCondition(id.startsWith(reference), 'Server answered about a different identity than the one requested.');
  return id;
}
export function messageID(value: unknown): string {
  requireCondition(typeof value === 'string' && UUID_PATTERN.test(value), 'Use a complete message UUID.');
  return value;
}
function timestamp(value: unknown): number {
  requireCondition(Number.isSafeInteger(value) && (value as number) > 0, 'Invalid server timestamp.');
  return value as number;
}
function counter(value: unknown): number {
  requireCondition(Number.isSafeInteger(value) && (value as number) >= 0, 'Invalid server count.');
  return value as number;
}
function array(value: unknown, maximum: number): unknown[] {
  requireCondition(Array.isArray(value) && value.length <= maximum, 'Invalid or oversized server list.');
  return value;
}
export interface PeerView extends Peer { inbound: boolean | null }
async function peer(value: unknown): Promise<PeerView> {
  const item = record(value);
  requireCondition(item.inbound === undefined || typeof item.inbound === 'boolean', 'Invalid peer grant direction.');
  return {
    name: name(item.name),
    identity: await validatePublicIdentity(item.identity),
    // A 0.2.x service omits inbound; unknown stays null rather than claiming replies fail.
    inbound: item.inbound === undefined ? null : item.inbound as boolean,
  };
}
interface Config { version: 1; server: string; role: 'agent' | 'admin'; adminKey: PublicIdentity | null; label: string | null }
export interface InboxReceipt { messages: (InboxItem & { untrusted: true })[]; transportOnly: true }
export interface HistoryItem { message: Message; status: 'pending' | 'acknowledged' | 'blocked'; untrusted: true }
export interface ReceiveOptions { wait: boolean; intervalSeconds?: number; spool?: string; ack: boolean }
export interface SendReceipt {
  id: string; duplicate: boolean;
  recipientPending: number | null;
  replyPossible: boolean | null;
  transportOnly: true;
}
export interface CapabilityCard {
  kind: 'capability-card'; name: string; clientVersion: string; nodeVersion: string;
  label: string | null; peersInbound: boolean;
}
export interface EnrollmentStatus {
  id: string; status: 'pending' | 'active' | 'revoked'; name: string | null; serverTime: number | null;
  adminKey: PublicIdentity | null; adminKeyPinned: 'trusted' | 'first-use' | 'replaced' | 'absent';
}
export interface NetworkStatus {
  agents: { id: string; name: string | null; status: string; unread: number; lastSeen: number | null }[];
  totals: { active: number; pending: number; revoked: number; messages: number; pendingMessages: number };
  // Absent from a pre-0.4.0 server, which counted nothing.
  usage: {
    day: string; rowsWritten: number; rowsWrittenLimit: number; percent: number;
    requests: number; brakeAt: number; resetInSeconds: number;
  } | null;
  quotaWarning: string | null;
}
// The pinned admin key is reported as a state word, never a raw fingerprint or null:
// what the key is matters more to an operator than its bytes, which status prints.
export type AdminKeyState = 'not-pinned' | 'first-use' | 'trusted' | 'replaced';
// Local health, update channel health, and mesh health are separate sections on purpose:
// an unreachable release host is not a broken mesh, and agents kept confusing the two.
export interface DoctorReport {
  local: {
    home: string; homeMode: string; homeOk: boolean; identityMode: string; identityOk: boolean;
    nodeVersion: string; nodeOk: boolean; label: string | null; adminKeyPinned: AdminKeyState;
  };
  config: { server: string; role: 'agent' | 'admin' };
  mesh: {
    enrollment: { status: string | null; name: string | null };
    peers: number | null; inboundPeers: number | null; pollHint: string | null;
    server: { reachable: boolean; roundTripMs: number; serverTime: number | null; clockSkewMs: number | null; error: string | null };
  };
  warnings: string[];
}
// The receipt echoes what was reserved (name) and what admits the agent (binding: the
// fingerprint, or 'any identity with the token'). stdout reports --out - mode, where
// the token is returned for printing and no file is created.
export interface InviteReceipt {
  path: string; stdout: boolean; token?: string;
  expiresAt: number; autoApprove: boolean;
  name: string | null; binding: string;
}

export class AgentClient {
  // Latest response Date header; the clock reference when a route returns no server time.
  private serverDate: number | null = null;
  private constructor(readonly home: string, readonly config: Config, private readonly identity: PrivateIdentity) {}

  static async init(homeValue: string, origin: string, admin: boolean, labelValue?: string): Promise<AgentClient> {
    const home = resolve(homeValue);
    const server = serverURL(origin);
    const role = admin ? 'admin' : 'agent';
    const chosen = labelValue === undefined || labelValue === '' ? null : label(labelValue);
    await privateDirectory(home, true);
    const entries = await readdir(home);
    if (entries.length !== 0) {
      requireCondition(entries.includes('identity.json') && entries.includes('config.json'), 'Home is not empty or initialization was interrupted. Nothing was overwritten. Choose a new empty home.');
      const existing = await AgentClient.load(home);
      requireCondition(existing.config.server === server && existing.config.role === role, 'Existing home has a different server or role. Use a separate home; identities cannot be reset.');
      // A label is local description, not identity, so repeating init may set it.
      if (chosen !== null && chosen !== existing.config.label) await existing.setLabel(chosen);
      return existing;
    }
    const identity = await generateIdentity();
    const config: Config = { version: 1, server, role, adminKey: null, label: chosen };
    await writeExclusive(join(home, 'identity.json'), JSON.stringify(identity) + '\n');
    await writeExclusive(join(home, 'config.json'), JSON.stringify(config) + '\n');
    await syncDirectory(home);
    return new AgentClient(home, config, identity);
  }

  static async load(homeValue: string): Promise<AgentClient> {
    const home = resolve(homeValue);
    await privateDirectory(home);
    const rawConfig = record(JSON.parse(await readFileSafely(join(home, 'config.json'), 8192)));
    requireCondition(rawConfig.version === 1 && (rawConfig.role === 'agent' || rawConfig.role === 'admin') && typeof rawConfig.server === 'string', 'Invalid local configuration.');
    const config: Config = {
      version: 1, server: serverURL(rawConfig.server), role: rawConfig.role,
      // Absent in a 0.2.x home: the next successful status call pins the admin key.
      adminKey: rawConfig.adminKey === undefined || rawConfig.adminKey === null ? null : await validatePublicIdentity(rawConfig.adminKey),
      label: rawConfig.label === undefined || rawConfig.label === null ? null : label(rawConfig.label),
    };
    const raw = record(JSON.parse(await readFileSafely(join(home, 'identity.json'), 8192)));
    const publicIdentity = await validatePublicIdentity(raw.public);
    const signing = record(raw.signingPrivateKey);
    requireCondition(signing.kty === 'OKP' && signing.crv === 'Ed25519' && signing.x === publicIdentity.signingKey.x && typeof signing.d === 'string' && /^[A-Za-z0-9_-]{43}$/.test(signing.d), 'Invalid private signing identity.');
    const identity: PrivateIdentity = { public: publicIdentity, signingPrivateKey: signing };
    const checkURL = config.server + '/v1/status';
    await verifyRequest(await signRequest(identity, checkURL, '{}'), publicIdentity, checkURL, '{}');
    return new AgentClient(home, config, identity);
  }

  publicIdentity(): PublicIdentity { return this.identity.public; }
  requireRole(role: 'agent' | 'admin'): void {
    requireCondition(this.config.role === role, role === 'admin' ? 'This command requires a separate admin home initialized with --admin.' : 'An admin identity cannot participate as an agent. Use a separate agent home.');
  }
  private async request(path: string, value: unknown = {}, options: { signal?: AbortSignal; timeout?: number } = {}): Promise<Record<string, unknown>> {
    await privateDirectory(this.home);
    const raw = JSON.stringify(value);
    requireCondition(Buffer.byteLength(raw) <= MAX_REQUEST_BYTES, 'Request exceeds the allowed size.');
    const url = this.config.server + path;
    const authorization = await signRequest(this.identity, url, raw);
    const abort = AbortSignal.any([AbortSignal.timeout(options.timeout ?? REQUEST_TIMEOUT), ...(options.signal ? [options.signal] : [])]);
    try {
      const response = await fetch(url, {
        method: 'POST', redirect: 'error', signal: abort,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${authorization}` }, body: raw,
      });
      const served = Date.parse(response.headers.get('date') ?? '');
      this.serverDate = Number.isSafeInteger(served) ? served : null;
      if (!response.ok) {
        // The server names its own failures. Discarding the body here is what turned the
        // storage-cap outage of 19 September into an unexplained HTTP 500 on every host.
        const length = response.headers.get('content-length');
        let cause = '';
        if (length === null || (/^\d+$/.test(length) && Number(length) <= 8192)) {
          try {
            const body = record(JSON.parse((await response.text()).slice(0, 8192)));
            const said = typeof body.error === 'string' ? body.error : '';
            const detail = typeof body.detail === 'string' ? ` ${body.detail}` : '';
            const code = typeof body.code === 'string' ? ` [${body.code}]` : '';
            const seconds = typeof body.retryAfterSeconds === 'number' && body.retryAfterSeconds > 0 ? body.retryAfterSeconds : 0;
            const retry = seconds === 0 ? ''
              : ` Retry after ${seconds < 3600 ? `${Math.ceil(seconds / 60)} minutes` : `${Math.round(seconds / 360) / 10} hours`}.`;
            if (said) cause = `: ${said}${code}.${detail}${retry}`;
          } catch { cause = ''; }
        } else {
          await response.body?.cancel();
        }
        throw new ClientError(`Server rejected the request (HTTP ${response.status})${cause || '.'}`);
      }
      const advertised = response.headers.get('content-length');
      if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > RESPONSE_LIMIT)) {
        await response.body?.cancel();
        throw new ClientError('Server response exceeds the allowed size.');
      }
      requireCondition(response.body, 'Server returned an empty response.');
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          bytes += part.value.byteLength;
          requireCondition(bytes <= RESPONSE_LIMIT, 'Server response exceeds the allowed size.');
          chunks.push(part.value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      return record(JSON.parse(decoder.decode(Buffer.concat(chunks, bytes))));
    } catch (error) {
      if (error instanceof ClientError) throw error;
      if (options.signal?.aborted) throw new ClientError('Cancelled.');
      const local = describeFileError(error);
      if (local !== null) throw new ClientError(local);
      throw new ClientError('Request failed, timed out, redirected, or returned invalid data.');
    }
  }
  private async writeConfig(next: Config): Promise<void> {
    await privateDirectory(this.home);
    await writeReplace(join(this.home, 'config.json'), JSON.stringify(next) + '\n');
    this.config.adminKey = next.adminKey;
    this.config.label = next.label;
  }
  async setLabel(value: string): Promise<{ label: string | null }> {
    const chosen = value === '' ? null : label(value);
    await this.writeConfig({ ...this.config, label: chosen });
    return { label: chosen };
  }
  // Trust on first use: the first answer from a server pins the admin key whose signature
  // authorizes client releases. A different key later is never accepted silently.
  private async pinAdminKey(observed: PublicIdentity | null, accept: boolean): Promise<EnrollmentStatus['adminKeyPinned']> {
    if (observed === null) return 'absent';
    const pinned = this.config.adminKey;
    if (pinned !== null && pinned.id === observed.id) return 'trusted';
    requireCondition(pinned === null || accept, `Admin key mismatch: this server presented ${observed.id}, not the key pinned in this home. This is a key rotation or an impersonated service; nothing changed. Verify the new key out of band, then run: agentnet trust-admin --accept-new-key`);
    await this.writeConfig({ ...this.config, adminKey: observed });
    return pinned === null ? 'first-use' : 'replaced';
  }
  private async fetchStatus(options: { wait?: boolean; signal?: AbortSignal } = {}): Promise<Omit<EnrollmentStatus, 'adminKeyPinned'>> {
    this.requireRole('agent');
    const wait = options.wait === true;
    const result = await this.request('/v1/status', wait ? { wait: true } : {}, { signal: options.signal, timeout: wait ? WAIT_TIMEOUT : REQUEST_TIMEOUT });
    requireCondition(result.id === this.identity.public.id && ['pending', 'active', 'revoked'].includes(String(result.status)), 'Invalid enrollment status.');
    return {
      id: this.identity.public.id,
      status: result.status as EnrollmentStatus['status'],
      name: result.name === null || result.name === undefined ? null : name(result.name),
      serverTime: result.serverTime === undefined ? null : timestamp(result.serverTime),
      // Public information, kept locally so a signed client release can be verified
      // without trusting whichever host served the update manifest.
      adminKey: result.adminKey === undefined || result.adminKey === null ? null : await validatePublicIdentity(result.adminKey),
    };
  }
  async status(options: { wait?: boolean; signal?: AbortSignal } = {}): Promise<EnrollmentStatus> {
    const observed = await this.fetchStatus(options);
    return { ...observed, adminKeyPinned: await this.pinAdminKey(observed.adminKey, false) };
  }
  async trustAdmin(acceptNewKey: boolean): Promise<{ adminKey: PublicIdentity; pinned: EnrollmentStatus['adminKeyPinned']; previous: string | null; status: EnrollmentStatus['status'] }> {
    const observed = await this.fetchStatus();
    const adminKey = observed.adminKey;
    requireCondition(adminKey, 'This service publishes no admin key, so there is nothing to pin. Client updates stay checksum verified.');
    const previous = this.config.adminKey === null ? null : this.config.adminKey.id;
    return { adminKey, pinned: await this.pinAdminKey(adminKey, acceptNewKey), previous, status: observed.status };
  }
  // An admin decision is a server event, so hold one request instead of asking a human
  // to poll. The held request returns unchanged after about 25 seconds and is reissued.
  async watchStatus(emit: (value: EnrollmentStatus) => Promise<void> | void, signal: AbortSignal): Promise<void> {
    const first = await this.status({ signal });
    await emit(first);
    if (first.status !== 'pending' || signal.aborted) return;
    while (!signal.aborted) {
      const started = Date.now();
      const current = await this.status({ wait: true, signal });
      if (signal.aborted) return;
      if (current.status !== first.status) { await emit(current); return; }
      const idle = IDLE_DELAY - (Date.now() - started);
      if (idle > 0) {
        try { await delay(idle, undefined, { signal }); }
        catch (error) { if (signal.aborted) return; throw error; }
      }
    }
  }
  async enroll(source: TextSource): Promise<{ id: string; status: 'pending' | 'active'; name: string | null }> {
    this.requireRole('agent');
    const invite = (await readSource(source, 1024, true)).trim();
    requireCondition(INVITE_PATTERN.test(invite), 'Provide a valid invitation token in a private file or on standard input.');
    const result = await this.request('/v1/enroll', { identity: this.identity.public, invite });
    requireCondition(result.id === this.identity.public.id && (result.status === 'pending' || result.status === 'active'), 'Invalid enrollment response.');
    const status = result.status as 'pending' | 'active';
    // An auto-approving invitation reserves the name, so the server names the agent right away.
    const assigned = status === 'active' ? name(result.name) : (result.name === null || result.name === undefined ? null : name(result.name));
    return { id: this.identity.public.id, status, name: assigned };
  }
  async peers(): Promise<PeerView[]> {
    this.requireRole('agent');
    const result = await this.request('/v1/peers');
    const peers = await Promise.all(array(result.peers, LIST_LIMIT).map(peer));
    requireCondition(new Set(peers.map(item => item.identity.id)).size === peers.length && new Set(peers.map(item => item.name)).size === peers.length, 'Server returned duplicate peers or names.');
    return peers;
  }
  private async resolvePeer(recipient: string): Promise<PeerView> {
    const target = (await this.peers()).find(item => item.identity.id === recipient || item.name === recipient);
    requireCondition(target, 'Recipient is not currently granted. Use peers to list allowed recipients.');
    return target;
  }
  private async deliver(target: PeerView, body: MessageBody): Promise<SendReceipt> {
    const message = createMessage(this.identity.public.id, target.identity.id, body);
    const result = await this.request('/v1/send', { message });
    requireCondition(result.id === message.id && typeof result.duplicate === 'boolean', 'Invalid send receipt.');
    return {
      id: message.id, duplicate: result.duplicate,
      // Backpressure: messages the recipient has not read yet, including this one.
      recipientPending: result.recipientPending === undefined ? null : counter(result.recipientPending),
      // Without a grant back an answer cannot be delivered, which is why a send can look
      // ignored. null means this service does not report the reverse grant.
      replyPossible: target.inbound,
      transportOnly: true,
    };
  }
  async send(recipient: string, source: TextSource, kind: MessageBody['kind']): Promise<SendReceipt> {
    this.requireRole('agent');
    messageKind(kind);
    const target = await this.resolvePeer(recipient);
    const text = await readSource(source, MAX_TEXT_BYTES, false);
    return this.deliver(target, { kind, text });
  }
  // A fixed shape built only from local facts. No caller text reaches the peer, so an
  // introduction adds no injection surface beyond what the transport already carries.
  async hello(recipient: string, clientVersion: string): Promise<SendReceipt & { card: CapabilityCard }> {
    this.requireRole('agent');
    requireCondition(VERSION_PATTERN.test(clientVersion), 'Invalid client version.');
    const target = await this.resolvePeer(recipient);
    const self = await this.status();
    requireCondition(self.status === 'active' && self.name !== null, 'Only an active, named identity can introduce itself.');
    const card: CapabilityCard = {
      kind: 'capability-card', name: self.name as string, clientVersion,
      nodeVersion: process.versions.node, label: this.config.label,
      peersInbound: target.inbound === true,
    };
    const receipt = await this.deliver(target, { kind: 'result', text: JSON.stringify(card) });
    return { ...receipt, card };
  }
  async inbox(options: { wait?: boolean; signal?: AbortSignal } = {}): Promise<InboxReceipt> {
    this.requireRole('agent');
    const wait = options.wait === true;
    const result = await this.request('/v1/inbox', wait ? { wait: true } : {}, { signal: options.signal, timeout: wait ? WAIT_TIMEOUT : REQUEST_TIMEOUT });
    const messages = await Promise.all(array(result.messages, 20).map(async value => {
      const item = record(value);
      const sender = await validatePublicIdentity(item.sender);
      const message = validateMessage(item.message, sender.id, this.identity.public.id);
      return { sender, message, senderName: name(item.senderName), untrusted: true as const };
    }));
    requireCondition(new Set(messages.map(item => item.message.id)).size === messages.length, 'Server returned duplicate message IDs.');
    return { messages, transportOnly: true };
  }
  async ack(idValue: string): Promise<{ acknowledged: number; transportOnly: true }> {
    this.requireRole('agent');
    const result = await this.request('/v1/ack', { ids: [messageID(idValue)] });
    requireCondition(result.acknowledged === 0 || result.acknowledged === 1, 'Invalid acknowledgment receipt.');
    return { acknowledged: result.acknowledged, transportOnly: true };
  }
  // Acknowledgment always follows durable delivery: a synced spool file when spooling,
  // otherwise a completed write to standard output. It reports receipt, never execution.
  async receive(emit: (value: InboxReceipt) => Promise<void> | void, options: ReceiveOptions, signal: AbortSignal): Promise<void> {
    this.requireRole('agent');
    const spool = options.spool === undefined ? undefined : resolve(options.spool);
    if (spool !== undefined) await privateDirectory(spool, true);
    const seen = new Set<string>();
    let first = true;
    while (!signal.aborted) {
      const started = Date.now();
      const receipt = await this.inbox({ wait: options.wait, signal });
      if (signal.aborted) return;
      const fresh: InboxReceipt['messages'] = [];
      for (const item of receipt.messages) {
        if (spool === undefined) {
          if (seen.has(item.message.id)) continue;
          seen.add(item.message.id);
        } else if (!await spoolMessage(spool, item)) continue;
        fresh.push(item);
      }
      if (first || fresh.length) await emit({ messages: fresh, transportOnly: true });
      first = false;
      if (options.ack) {
        for (const item of fresh) {
          if (signal.aborted) return;
          await this.ack(item.message.id);
        }
      }
      if (!(options.wait || options.intervalSeconds !== undefined) || signal.aborted) return;
      // A held request keeps the server object awake for its whole window; an interval
      // poll wakes it for milliseconds. The idle floor keeps a held loop from spinning.
      const pause = options.intervalSeconds === undefined
        ? (fresh.length === 0 ? IDLE_DELAY - (Date.now() - started) : 0)
        : options.intervalSeconds * 1000 - (Date.now() - started);
      if (pause > 0) {
        try { await delay(pause, undefined, { signal }); }
        catch (error) { if (signal.aborted) return; throw error; }
      }
    }
  }
  async doctor(): Promise<DoctorReport> {
    const warnings: string[] = [];
    let homeMode = '----';
    let homeOk = true;
    try {
      await privateDirectory(this.home);
      homeMode = ((await lstat(this.home)).mode & 0o7777).toString(8).padStart(4, '0');
    } catch { homeOk = false; warnings.push('Home directory is missing, not yours, or not mode 0700.'); }
    // The private key file is the whole identity, so its mode is checked on its own:
    // a later chmod is invisible until some command refuses to read it.
    let identityMode = '----';
    let identityOk = false;
    const identityPath = join(this.home, 'identity.json');
    try {
      const stat = await inspect(identityPath);
      if (stat) {
        identityMode = (stat.mode & 0o7777).toString(8).padStart(4, '0');
        identityOk = stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === uid() && (stat.mode & 0o7777) === 0o600;
      }
    } catch { /* an unreadable home is already reported above */ }
    if (!identityOk) warnings.push(`identity.json must be a regular file you own with mode 0600; it is ${identityMode}. Fix it with: chmod 600 ${identityPath}`);
    const nodeVersion = process.versions.node;
    const nodeOk = Number(nodeVersion.split('.')[0]) >= 22;
    if (!nodeOk) warnings.push(`Node.js ${nodeVersion} is older than the required Node.js 22, so this client cannot run reliably.`);
    let enrollment: { status: string | null; name: string | null } = { status: null, name: null };
    // The pinned admin key is reported as a state word, never null: a diagnostic must
    // always say what the key situation is. 'replaced' can only come from trust-admin,
    // so it never appears here, but the value space stays the same for every home.
    let pinnedState: AdminKeyState = this.config.adminKey === null ? 'not-pinned' : 'trusted';
    let serverTime: number | null = null;
    let reachable = false;
    let serverError: string | null = null;
    const before = Date.now();
    try {
      if (this.config.role === 'agent') {
        const result = await this.fetchStatus();
        enrollment = { status: result.status, name: result.name };
        serverTime = result.serverTime;
        // A mismatched admin key is reported, never thrown: a diagnostic must still print.
        try {
          const pinned = await this.pinAdminKey(result.adminKey, false);
          if (pinned !== 'absent' && pinned !== 'trusted') pinnedState = pinned;
          if (pinned === 'first-use') warnings.push(`Pinned this service's admin key on first use. Verify that fingerprint with the owner before trusting a signed client update.`);
        } catch (error) { warnings.push(error instanceof ClientError ? error.message : 'Admin key check failed.'); }
      } else {
        const network = await this.adminStatus();
        if (network.quotaWarning !== null) warnings.push(network.quotaWarning);
        // An admin home has no enrollment; name the role so status never prints null.
        enrollment = { status: 'admin', name: null };
      }
      reachable = true;
    } catch (error) { serverError = error instanceof ClientError ? error.message : 'Server request failed.'; }
    const after = Date.now();
    const observed = serverTime ?? (reachable ? this.serverDate : null);
    const clockSkewMs = observed === null ? null : observed - Math.round((before + after) / 2);
    let peers: number | null = null;
    let inboundPeers: number | null = null;
    if (enrollment.status === 'active') {
      try {
        const listed = await this.peers();
        peers = listed.length;
        // null only when the service does not report reverse grants at all.
        inboundPeers = listed.some(item => item.inbound === null) ? null : listed.filter(item => item.inbound === true).length;
      } catch { warnings.push('Peer list could not be read even though this identity is active.'); }
    }
    if (peers !== null && peers > 0 && inboundPeers === 0) {
      warnings.push('No peer may send to this identity, so nothing can answer what it sends. Ask an admin for the reverse grant (admin grant PEER ME) or a mesh.');
    }
    if (this.config.role === 'agent' && this.config.adminKey === null) {
      warnings.push('No admin key is pinned in this home, so a client update can only be checksum verified, not traced to the admin. A successful status call pins it.');
    }
    if (!reachable) warnings.push(`Server ${this.config.server} could not be reached. Commands that talk to the network will fail.`);
    if (clockSkewMs !== null && Math.abs(clockSkewMs) > CLOCK_WARNING) {
      warnings.push(`This machine's clock differs from the server by about ${Math.round(clockSkewMs / 1000)} seconds. Signed requests carry a 60 second validity window, so every command fails once the difference passes that tolerance. Synchronize the system clock.`);
    }
    if (enrollment.status === 'pending') warnings.push('This identity is still pending. An admin must approve it before sending or receiving.');
    if (enrollment.status === 'revoked') warnings.push('This identity is revoked permanently. Initialize a new home to rejoin.');
    const pollHint = enrollment.status === 'active'
      ? 'Run receive --interval 60 --spool DIR --ack from a supervisor. A held request (--wait) delivers in about a second but keeps the server object awake for 25 seconds per call, which is what the free tier charges for; an interval poll costs milliseconds and delivers within the interval.'
      : enrollment.status === 'pending' ? 'Run status --watch to wait for an admin decision instead of polling status.' : null;
    return {
      local: {
        home: this.home, homeMode, homeOk, identityMode, identityOk, nodeVersion, nodeOk,
        label: this.config.label, adminKeyPinned: pinnedState,
      },
      config: { server: this.config.server, role: this.config.role },
      mesh: {
        enrollment, peers, inboundPeers, pollHint,
        server: { reachable, roundTripMs: after - before, serverTime, clockSkewMs, error: serverError },
      },
      warnings,
    };
  }
  async archive(): Promise<{ archive: string; networkRevoked: false }> {
    requireCondition(process.stdin.isTTY && process.stdout.isTTY && process.stderr.isTTY, 'Remove requires an interactive terminal. There is no noninteractive approval option.');
    const expected = `REMOVE ${this.identity.public.id}`;
    const terminal = createInterface({ input: process.stdin, output: process.stderr });
    const controller = new AbortController();
    terminal.on('SIGINT', () => controller.abort());
    try {
      const answer = await terminal.question(`Archive this local identity without deleting it. The server will still consider it enrolled until an admin revokes it.\nType ${expected}\n> `, { signal: controller.signal });
      requireCondition(answer === expected, 'Removal was not approved.');
    } finally { terminal.close(); }
    await privateDirectory(this.home);
    const archive = `${this.home}.archive-${new Date().toISOString().replaceAll(':', '-')}-${randomUUID()}`;
    await mkdir(archive, { mode: 0o700 });
    // This destination is our exclusive empty reservation, never an existing user directory.
    await rename(this.home, archive);
    await syncDirectory(dirname(this.home));
    return { archive, networkRevoked: false };
  }
  // An invitation receipt names what was reserved and what admits the agent, so an admin
  // knows whether a leaked token is usable by anyone else. --out - prints the token to
  // standard output and writes no file; the token is only carried in the receipt then.
  async adminInvite(outValue: string, options: { name?: string; autoApprove?: boolean; for?: string } = {}): Promise<InviteReceipt> {
    this.requireRole('admin');
    const reserved = options.name === undefined ? null : name(options.name);
    const autoApprove = options.autoApprove === true;
    // A bound invitation is the safe default for a known agent: a leaked token is useless
    // to anyone else because only that fingerprint can consume it.
    const bound = options.for === undefined ? null : identityID(options.for);
    requireCondition(!autoApprove || reserved !== null, 'An auto-approving invitation must reserve a name with --name.');
    const toStdout = outValue === '-';
    const path = toStdout ? outValue : resolve(outValue);
    if (!toStdout) {
      await checkParents(path);
      requireCondition(!(await inspect(path)), 'Invitation output already exists. It was not overwritten.');
    }
    const body: Record<string, unknown> = {};
    if (reserved !== null) body.name = reserved;
    if (autoApprove) body.autoApprove = true;
    if (bound !== null) body.for = bound;
    const result = await this.request('/v1/admin/invite', body);
    requireCondition(typeof result.invite === 'string' && INVITE_PATTERN.test(result.invite), 'Invalid invitation response.');
    const expiresAt = timestamp(result.expiresAt);
    const named = result.name === null || result.name === undefined ? null : name(result.name);
    const automatic = result.autoApprove === true;
    const echoed = result.for === null || result.for === undefined ? null : identityID(result.for);
    requireCondition(named === reserved && automatic === autoApprove && echoed === bound, 'Server created a different invitation than the one requested.');
    if (toStdout) return { path, stdout: true, token: result.invite, expiresAt, autoApprove: automatic, name: named, binding: echoed === null ? 'any identity with the token' : echoed };
    await writeExclusive(path, result.invite + '\n');
    return { path, stdout: false, expiresAt, autoApprove: automatic, name: named, binding: echoed === null ? 'any identity with the token' : echoed };
  }
  async adminList(command: 'pending' | 'agents' | 'audit', options: { wait?: boolean } = {}): Promise<unknown> {
    this.requireRole('admin');
    // Only pending supports a held request: an admin can wait for the next enrollment.
    const wait = command === 'pending' && options.wait === true;
    const result = await this.request('/v1/admin/' + command, wait ? { wait: true } : {}, wait ? { timeout: WAIT_TIMEOUT } : {});
    if (command === 'audit') {
      const events = array(result.events, 1000).map(value => {
        const event = record(value);
        requireCondition(typeof event.action === 'string' && /^[a-z][a-z0-9_.:-]{0,63}$/.test(event.action) && typeof event.subject === 'string' && event.subject.length <= 256 && /^[a-zA-Z0-9_ .:>\/-]*$/.test(event.subject), 'Invalid audit metadata.');
        return { time: timestamp(event.time), action: event.action, subject: event.subject };
      });
      return { events };
    }
    const agents = await Promise.all(array(result.agents, LIST_LIMIT).map(async value => {
      const item = record(value);
      const identity = await validatePublicIdentity(item.identity);
      const createdAt = timestamp(item.createdAt);
      if (command === 'pending') return { identity, createdAt };
      requireCondition(['pending', 'active', 'revoked'].includes(String(item.status)), 'Invalid agent status.');
      return { identity, createdAt, status: item.status as string, name: item.name === null ? null : name(item.name) };
    }));
    return { agents };
  }
  async adminStatus(): Promise<NetworkStatus> {
    this.requireRole('admin');
    const result = await this.request('/v1/admin/status');
    const agents = array(result.agents, LIST_LIMIT).map(value => {
      const item = record(value);
      requireCondition(['pending', 'active', 'revoked'].includes(String(item.status)), 'Invalid agent status.');
      // 0.3.1 renamed the per-agent unread count from pending; accept either shape and
      // always expose it as unread so a stale server never breaks the client.
      return {
        id: identityID(item.id),
        name: item.name === null ? null : name(item.name),
        status: item.status as string,
        unread: counter(item.unread === undefined ? item.pending : item.unread),
        lastSeen: item.lastSeen === null ? null : timestamp(item.lastSeen),
      };
    });
    const totals = record(result.totals);
    const raw = result.usage === undefined || result.usage === null ? null : record(result.usage);
    const usage = raw === null ? null : {
      day: String(raw.day), rowsWritten: counter(raw.rowsWritten), rowsWrittenLimit: counter(raw.rowsWrittenLimit),
      percent: counter(Math.round(Number(raw.percent) * 10)) / 10, requests: counter(raw.requests),
      brakeAt: counter(raw.brakeAt), resetInSeconds: counter(raw.resetInSeconds),
    };
    // The cap that stopped this service is a daily one, so the warning has to arrive
    // during the day it is being spent, not in tomorrow's post mortem.
    const resets = usage === null || usage.resetInSeconds < 3600
      ? `${Math.ceil((usage?.resetInSeconds ?? 0) / 60)} minutes` : `${Math.round(usage.resetInSeconds / 360) / 10} hours`;
    const quotaWarning = usage === null || usage.rowsWrittenLimit === 0 || usage.percent < 70 ? null
      : `The network has written ${usage.rowsWritten} of its ${usage.rowsWrittenLimit} daily rows (${usage.percent}%). Optional work stops at ${usage.brakeAt}. The counter resets in ${resets}.`;
    return {
      agents,
      totals: {
        active: counter(totals.active), pending: counter(totals.pending), revoked: counter(totals.revoked),
        messages: counter(totals.messages), pendingMessages: counter(totals.pendingMessages),
      },
      usage,
      quotaWarning,
    };
  }
  async adminMessages(agent?: string): Promise<{ messages: HistoryItem[] }> {
    this.requireRole('admin');
    const result = await this.request('/v1/admin/messages', agent === undefined ? {} : { agent: identityReference(agent) });
    const messages = array(result.messages, 100).map(value => {
      const item = record(value);
      const raw = record(item.message);
      const message = validateMessage(raw, identityID(raw.from), identityID(raw.to));
      const rawStatus = item.status;
      requireCondition(rawStatus === 'pending' || rawStatus === 'acknowledged' || rawStatus === 'blocked', 'Invalid message history status.');
      return { message, status: rawStatus as HistoryItem['status'], untrusted: true as const };
    });
    return { messages };
  }
  // Names are convenient locally; only identity fingerprints or prefixes reach the server.
  private async resolveIdentities(values: string[]): Promise<string[]> {
    const ungrouped = values.map(ungroupIdentity);
    const named = ungrouped.filter(value => !REFERENCE_PATTERN.test(value));
    const byName = new Map<string, string>();
    if (named.length) {
      const listed = await this.adminList('agents') as { agents: { identity: { id: string }; status: string; name: string | null }[] };
      for (const agent of listed.agents) {
        if (agent.status === 'active' && agent.name !== null) byName.set(agent.name, agent.identity.id);
      }
    }
    const resolved = ungrouped.map(value => {
      if (REFERENCE_PATTERN.test(value)) return value;
      const id = byName.get(name(value));
      requireCondition(id, `No active agent is named ${value}.`);
      return id as string;
    });
    requireCondition(new Set(resolved).size === resolved.length, 'The same identity was listed more than once.');
    return resolved;
  }
  // A reference may be a full fingerprint or a unique prefix; enrolled identities are the
  // only namespace that can complete it, so resolution reads the same list an admin sees.
  private async resolveReference(reference: string): Promise<string> {
    const listed = await this.adminList('agents') as { agents: { identity: { id: string } }[] };
    const matches = listed.agents.filter(agent => agent.identity.id.startsWith(reference));
    requireCondition(matches.length === 1, matches.length === 0
      ? 'No enrolled identity matches that reference.'
      : 'That reference is ambiguous; give more characters.');
    return matches[0]!.identity.id;
  }
  async adminPeers(idValue: string): Promise<{ peers: PeerView[] }> {
    this.requireRole('admin');
    const id = await this.resolveReference(identityReference(idValue));
    const result = await this.request('/v1/admin/peers', { id });
    return { peers: await Promise.all(array(result.peers, LIST_LIMIT).map(peer)) };
  }
  async adminFingerprint(idValue: string): Promise<{ id: string; grouped: string }> {
    this.requireRole('admin');
    const id = await this.resolveReference(identityReference(idValue));
    return { id, grouped: groupedFingerprint(id) };
  }
  async adminApprove(idValue: string, nameValue: string, grantWith: string[] = []): Promise<{ id: string; status: 'active'; name: string; mutualGrants: number }> {
    this.requireRole('admin');
    const reference = identityReference(idValue);
    const label = name(nameValue);
    requireCondition(grantWith.length <= 16, 'At most 16 identities may be granted with an approval.');
    const partners = grantWith.length ? await this.resolveIdentities(grantWith) : [];
    const body: Record<string, unknown> = { id: reference, name: label };
    if (partners.length) body.grantWith = partners;
    const result = await this.request('/v1/admin/approve', body);
    const id = resolvedID(result.id, reference);
    requireCondition(result.status === 'active' && result.name === label, 'Invalid approval receipt.');
    return { id, status: 'active', name: label, mutualGrants: result.mutualGrants === undefined ? 0 : counter(result.mutualGrants) };
  }
  async adminMesh(values: string[]): Promise<{ ids: string[]; edges: number }> {
    this.requireRole('admin');
    requireCondition(values.length >= 2 && values.length <= 16, 'Mesh requires between 2 and 16 identities.');
    const ids = await this.resolveIdentities(values);
    const result = await this.request('/v1/admin/mesh', { ids });
    return { ids, edges: counter(result.edges) };
  }
  async adminRename(idValue: string, nameValue: string): Promise<{ id: string; name: string }> {
    this.requireRole('admin');
    const reference = identityReference(idValue);
    const label = name(nameValue);
    const result = await this.request('/v1/admin/rename', { id: reference, name: label });
    requireCondition(result.name === label, 'Invalid rename receipt.');
    return { id: resolvedID(result.id, reference), name: label };
  }
  async adminRevoke(idValue: string): Promise<{ id: string; status: 'revoked' }> {
    this.requireRole('admin');
    const reference = identityReference(idValue);
    const result = await this.request('/v1/admin/revoke', { id: reference });
    requireCondition(result.status === 'revoked', 'Invalid revocation receipt.');
    return { id: resolvedID(result.id, reference), status: 'revoked' };
  }
  async adminGrant(fromValue: string, toValue: string, allow: boolean): Promise<{ from: string; to: string; allow: boolean }> {
    this.requireRole('admin');
    const from = identityReference(fromValue), to = identityReference(toValue);
    const result = await this.request('/v1/admin/grant', { from, to, allow });
    requireCondition(result.allow === allow, 'Invalid grant receipt.');
    return { from: resolvedID(result.from, from), to: resolvedID(result.to, to), allow };
  }
}
