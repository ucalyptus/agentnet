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
const RESPONSE_LIMIT = 4 * 1024 * 1024;
const decoder = new TextDecoder('utf-8', { fatal: true });
export const DEFAULT_HOME = join(homedir(), '.local', 'share', 'agentnet');
export class ClientError extends Error {}
export function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new ClientError(message);
}
function isCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}
function uid(): number {
  requireCondition(typeof process.getuid === 'function', 'A POSIX filesystem with owner permissions is required.');
  return process.getuid();
}
function checkDirectory(stat: Stats, privateDirectory: boolean): void {
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(), 'A directory is missing or is a symbolic link.');
  if (privateDirectory) {
    requireCondition(stat.uid === uid() && (stat.mode & 0o7777) === 0o700, 'Agent directories must be owned by you and have mode 0700.');
  } else {
    const stickyRoot = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    requireCondition((stat.uid === uid() || stat.uid === 0) && ((stat.mode & 0o022) === 0 || stickyRoot), 'A parent directory has unsafe ownership or write permissions.');
  }
}
async function inspect(path: string): Promise<Stats | undefined> {
  try { return await lstat(path); } catch (error) { if (isCode(error, 'ENOENT')) return undefined; throw error; }
}
async function checkParents(path: string, create = false): Promise<void> {
  const parent = dirname(resolve(path));
  const root = parse(parent).root;
  checkDirectory(await lstat(root), false);
  let current = root;
  for (const part of parent.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part);
    let stat = await inspect(current);
    if (!stat && create) {
      try { await mkdir(current, { mode: 0o700 }); } catch (error) { if (!isCode(error, 'EEXIST')) throw error; }
      stat = await lstat(current);
    }
    requireCondition(stat, 'A parent directory does not exist.');
    checkDirectory(stat, false);
  }
}
async function privateDirectory(path: string, create = false): Promise<void> {
  await checkParents(path, create);
  if (create) {
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (!isCode(error, 'EEXIST')) throw error; }
  }
  checkDirectory(await lstat(path), true);
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
async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
// Publish a complete synced file without replacing an existing path.
async function writeExclusive(path: string, text: string): Promise<void> {
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
  try { await link(temporary, path); }
  finally { await unlink(temporary); }
  await syncDirectory(dirname(path));
}
function name(value: unknown): string {
  requireCondition(typeof value === 'string' && NAME_PATTERN.test(value), 'Invalid agent name.');
  return value;
}
export function identityID(value: unknown): string {
  requireCondition(typeof value === 'string' && ID_PATTERN.test(value), 'Use the complete 64-character identity fingerprint.');
  return value;
}
export function messageID(value: unknown): string {
  requireCondition(typeof value === 'string' && UUID_PATTERN.test(value), 'Use a complete message UUID.');
  return value;
}
function timestamp(value: unknown): number {
  requireCondition(Number.isSafeInteger(value) && (value as number) > 0, 'Invalid server timestamp.');
  return value as number;
}
function array(value: unknown, maximum: number): unknown[] {
  requireCondition(Array.isArray(value) && value.length <= maximum, 'Invalid or oversized server list.');
  return value;
}
async function peer(value: unknown): Promise<Peer> {
  const item = record(value);
  return { name: name(item.name), identity: await validatePublicIdentity(item.identity) };
}
interface Config { version: 1; server: string; role: 'agent' | 'admin' }
export interface InboxReceipt { messages: (InboxItem & { untrusted: true })[]; transportOnly: true }
export interface HistoryItem { message: Message; status: 'pending' | 'acknowledged' | 'blocked'; untrusted: true }

export class AgentClient {
  private constructor(readonly home: string, readonly config: Config, private readonly identity: PrivateIdentity) {}

  static async init(homeValue: string, origin: string, admin: boolean): Promise<AgentClient> {
    const home = resolve(homeValue);
    const server = serverURL(origin);
    const role = admin ? 'admin' : 'agent';
    await privateDirectory(home, true);
    const entries = await readdir(home);
    if (entries.length !== 0) {
      requireCondition(entries.includes('identity.json') && entries.includes('config.json'), 'Home is not empty or initialization was interrupted. Nothing was overwritten. Choose a new empty home.');
      const existing = await AgentClient.load(home);
      requireCondition(existing.config.server === server && existing.config.role === role, 'Existing home has a different server or role. Use a separate home; identities cannot be reset.');
      return existing;
    }
    const identity = await generateIdentity();
    const config: Config = { version: 1, server, role };
    await writeExclusive(join(home, 'identity.json'), JSON.stringify(identity) + '\n');
    await writeExclusive(join(home, 'config.json'), JSON.stringify(config) + '\n');
    await syncDirectory(home);
    return new AgentClient(home, config, identity);
  }

  static async load(homeValue: string): Promise<AgentClient> {
    const home = resolve(homeValue);
    await privateDirectory(home);
    const rawConfig = record(JSON.parse(await readFileSafely(join(home, 'config.json'), 4096)));
    requireCondition(rawConfig.version === 1 && (rawConfig.role === 'agent' || rawConfig.role === 'admin') && typeof rawConfig.server === 'string', 'Invalid local configuration.');
    const config: Config = { version: 1, server: serverURL(rawConfig.server), role: rawConfig.role };
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
  private async request(path: string, value: unknown = {}, signal?: AbortSignal): Promise<Record<string, unknown>> {
    await privateDirectory(this.home);
    const raw = JSON.stringify(value);
    requireCondition(Buffer.byteLength(raw) <= MAX_REQUEST_BYTES, 'Request exceeds the allowed size.');
    const url = this.config.server + path;
    const authorization = await signRequest(this.identity, url, raw);
    const abort = AbortSignal.any([AbortSignal.timeout(15_000), ...(signal ? [signal] : [])]);
    try {
      const response = await fetch(url, {
        method: 'POST', redirect: 'error', signal: abort,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${authorization}` }, body: raw,
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new ClientError(`Server rejected the request (HTTP ${response.status}).`);
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
      if (signal?.aborted) throw new ClientError('Cancelled.');
      throw new ClientError('Request failed, timed out, redirected, or returned invalid data.');
    }
  }
  async status(): Promise<{ id: string; status: string; name: string | null }> {
    this.requireRole('agent');
    const result = await this.request('/v1/status');
    requireCondition(result.id === this.identity.public.id && ['pending', 'active', 'revoked'].includes(String(result.status)), 'Invalid enrollment status.');
    return { id: this.identity.public.id, status: result.status as string, name: result.name === null ? null : name(result.name) };
  }
  async enroll(invitePath: string): Promise<{ id: string; status: 'pending' }> {
    this.requireRole('agent');
    const invite = (await readFileSafely(resolve(invitePath), 1024)).trim();
    requireCondition(/^[A-Za-z0-9_-]{32,256}$/.test(invite), 'Invitation file must contain a valid invitation token.');
    const result = await this.request('/v1/enroll', { identity: this.identity.public, invite });
    requireCondition(result.id === this.identity.public.id && result.status === 'pending', 'Invalid enrollment response.');
    return { id: this.identity.public.id, status: 'pending' };
  }
  async peers(): Promise<Peer[]> {
    this.requireRole('agent');
    const result = await this.request('/v1/peers');
    const peers = await Promise.all(array(result.peers, 1000).map(peer));
    requireCondition(new Set(peers.map(item => item.identity.id)).size === peers.length && new Set(peers.map(item => item.name)).size === peers.length, 'Server returned duplicate peers or names.');
    return peers;
  }
  async send(recipient: string, file: string, kind: MessageBody['kind']): Promise<{ id: string; duplicate: boolean; transportOnly: true }> {
    this.requireRole('agent');
    const target = (await this.peers()).find(item => item.identity.id === recipient || item.name === recipient);
    requireCondition(target, 'Recipient is not currently granted. Use peers to list allowed recipients.');
    requireCondition(['message', 'prompt', 'instruction'].includes(kind), 'Invalid message kind.');
    const text = await readFileSafely(resolve(file), MAX_TEXT_BYTES, false);
    const message = createMessage(this.identity.public.id, target.identity.id, { kind, text });
    const result = await this.request('/v1/send', { message });
    requireCondition(result.id === message.id && typeof result.duplicate === 'boolean', 'Invalid send receipt.');
    return { id: message.id, duplicate: result.duplicate, transportOnly: true };
  }
  async inbox(signal?: AbortSignal): Promise<InboxReceipt> {
    this.requireRole('agent');
    const result = await this.request('/v1/inbox', {}, signal);
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
  async receive(onReceipt: (value: InboxReceipt) => void, wait: boolean, signal: AbortSignal): Promise<void> {
    const seen = new Set<string>();
    let first = true;
    do {
      if (signal.aborted) return;
      const receipt = await this.inbox(signal);
      const messages = receipt.messages.filter(item => !seen.has(item.message.id));
      for (const item of messages) seen.add(item.message.id);
      if (first || messages.length) onReceipt({ messages, transportOnly: true });
      first = false;
      if (!wait || signal.aborted) return;
      try { await delay(5000, undefined, { signal }); }
      catch (error) { if (signal.aborted) return; throw error; }
    } while (!signal.aborted);
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
  async adminInvite(outValue: string): Promise<{ path: string; expiresAt: number }> {
    this.requireRole('admin');
    const path = resolve(outValue);
    await checkParents(path);
    requireCondition(!(await inspect(path)), 'Invitation output already exists. It was not overwritten.');
    const result = await this.request('/v1/admin/invite');
    requireCondition(typeof result.invite === 'string' && /^[A-Za-z0-9_-]{32,256}$/.test(result.invite), 'Invalid invitation response.');
    const expiresAt = timestamp(result.expiresAt);
    await writeExclusive(path, result.invite + '\n');
    return { path, expiresAt };
  }
  async adminList(command: 'pending' | 'agents' | 'audit'): Promise<unknown> {
    this.requireRole('admin');
    const result = await this.request('/v1/admin/' + command);
    if (command === 'audit') {
      const events = array(result.events, 1000).map(value => {
        const event = record(value);
        requireCondition(typeof event.action === 'string' && /^[a-z][a-z0-9_.:-]{0,63}$/.test(event.action) && typeof event.subject === 'string' && event.subject.length <= 256 && /^[a-zA-Z0-9_ .:>\/-]*$/.test(event.subject), 'Invalid audit metadata.');
        return { time: timestamp(event.time), action: event.action, subject: event.subject };
      });
      return { events };
    }
    const agents = await Promise.all(array(result.agents, 1000).map(async value => {
      const item = record(value);
      const identity = await validatePublicIdentity(item.identity);
      const createdAt = timestamp(item.createdAt);
      if (command === 'pending') return { identity, createdAt };
      requireCondition(['pending', 'active', 'revoked'].includes(String(item.status)), 'Invalid agent status.');
      return { identity, createdAt, status: item.status as string, name: item.name === null ? null : name(item.name) };
    }));
    return { agents };
  }
  async adminMessages(agent?: string): Promise<{ messages: HistoryItem[] }> {
    this.requireRole('admin');
    const result = await this.request('/v1/admin/messages', agent === undefined ? {} : { agent: identityID(agent) });
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
  async adminApprove(idValue: string, nameValue: string): Promise<{ id: string; status: 'active'; name: string }> {
    this.requireRole('admin');
    const id = identityID(idValue);
    const label = name(nameValue);
    const result = await this.request('/v1/admin/approve', { id, name: label });
    requireCondition(result.id === id && result.status === 'active' && result.name === label, 'Invalid approval receipt.');
    return { id, status: 'active', name: label };
  }
  async adminRename(idValue: string, nameValue: string): Promise<{ id: string; name: string }> {
    this.requireRole('admin');
    const id = identityID(idValue);
    const label = name(nameValue);
    const result = await this.request('/v1/admin/rename', { id, name: label });
    requireCondition(result.id === id && result.name === label, 'Invalid rename receipt.');
    return { id, name: label };
  }
  async adminRevoke(idValue: string): Promise<{ id: string; status: 'revoked' }> {
    this.requireRole('admin');
    const id = identityID(idValue);
    const result = await this.request('/v1/admin/revoke', { id });
    requireCondition(result.id === id && result.status === 'revoked', 'Invalid revocation receipt.');
    return { id, status: 'revoked' };
  }
  async adminGrant(fromValue: string, toValue: string, allow: boolean): Promise<{ from: string; to: string; allow: boolean }> {
    this.requireRole('admin');
    const from = identityID(fromValue), to = identityID(toValue);
    const result = await this.request('/v1/admin/grant', { from, to, allow });
    requireCondition(result.from === from && result.to === to && result.allow === allow, 'Invalid grant receipt.');
    return { from, to, allow };
  }
}
