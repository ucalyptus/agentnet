import { DurableObject } from 'cloudflare:workers';
import { base64url, decodeJwt } from 'jose';
import {
  ID_PATTERN, MAX_IDENTITIES, MAX_REQUEST_BYTES, UUID_PATTERN,
  record, sha256, validateMessage, validatePublicIdentity, verifyRequest,
  type Message, type PublicIdentity,
} from './protocol.ts';

export interface Env {
  NETWORK: DurableObjectNamespace<Network>;
  ASSETS: Fetcher;
  ADMIN_IDENTITY?: string;
  // Daily rows-written ceiling this object holds itself to. The Workers Free plan stops
  // the object at 100,000; set it to 0 on a paid plan to disable the brake entirely.
  ROWS_WRITTEN_LIMIT?: string;
}

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const PENDING_TTL = 24 * 60 * MINUTE;
const INVITE_TTL = 60 * MINUTE;
const AUDIT_TTL = 30 * 24 * 60 * MINUTE;
const HOLD_WINDOW = 25_000;
const MAX_WAITERS = 4;
// Expired rows are filtered by every read, so deleting them is housekeeping, not
// correctness. Sweeping on each request cost six write statements per request.
const CLEANUP_INTERVAL = 10 * MINUTE;
// last_seen is an operator display, not a protocol value: minute-exact is enough.
const LAST_SEEN_RESOLUTION = 5 * MINUTE;
const DEFAULT_ROWS_WRITTEN_LIMIT = 100_000;
// Rows of usage that may be lost to an eviction before the meter is checkpointed.
const METER_FLUSH = 250;
// Above this share of the daily ceiling, optional work (sends, long polls) is refused so
// the remaining budget serves delivery and administration.
const BRAKE_SHARE = 0.95;
const STORAGE_LIMIT_PATTERN = /exceed|limit|quota|overload/i;
// Long poll registry keys are namespaced, so an identity's inbox and status holds are
// independent. New enrollments share one key: only the administrator waits on them.
const PENDING_KEY = 'enrollment';
const API_PATHS: Record<string, true> = {
  '/v1/enroll': true, '/v1/status': true, '/v1/peers': true,
  '/v1/send': true, '/v1/inbox': true, '/v1/ack': true,
  '/v1/admin/invite': true, '/v1/admin/pending': true, '/v1/admin/approve': true, '/v1/admin/rename': true,
  '/v1/admin/revoke': true, '/v1/admin/grant': true, '/v1/admin/agents': true, '/v1/admin/peers': true,
  '/v1/admin/audit': true, '/v1/admin/messages': true, '/v1/admin/mesh': true, '/v1/admin/status': true,
};
const ASSET_PATHS: Record<string, true> = {
  '/about.md': true, '/about.txt': true, '/agentnet.mjs': true,
  '/agentnet.sha256': true, '/install.sh': true, '/version.json': true,
};
const NAME_PATTERN = /^[a-z][a-z0-9-]{0,47}$/;
const INVITE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ID_PREFIX_PATTERN = /^[a-f0-9]{16,64}$/;
const RESPONSE_HEADERS = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const encoder = new TextEncoder();

type AgentRow = {
  id: string;
  identity: string;
  name: string | null;
  status: 'pending' | 'active' | 'revoked';
  created_at: number;
  expires_at: number | null;
  last_seen: number | null;
};
type InvitationRow = { hash: string; expires_at: number; name: string | null; auto_approve: number | null; bound_id: string | null };
type InboxRow = { message: string; identity: string; name: string };
// Returned by a long-polling read that found nothing yet, so the caller can wait unlocked.
// resume() re-reads once the hold ends: null means the wait is not satisfied and must
// continue, and an expired hold always produces a response.
type Hold = { key: string; resume: (expired: boolean) => Response | null };
type Authenticated = {
  identity: PublicIdentity;
  admin: boolean;
  adminKey: PublicIdentity;
  nonce: string;
  invitationHash: string | undefined;
};

class HttpError extends Error {
  constructor(readonly status: number, readonly code?: string, readonly retryAfter?: number) { super('Request rejected'); }
}

function requireValue(condition: unknown, status = 400, code?: string): asserts condition {
  if (!condition) throw new HttpError(status, code);
}

function json(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(value, { status, headers: { ...RESPONSE_HEADERS, ...headers } });
}

// Free-tier daily counters reset at 00:00 UTC, so that is the only honest retry time.
function untilReset(now: number): number {
  return Math.ceil((Math.floor(now / DAY) * DAY + DAY - now) / 1000);
}

function messagePage<T>(rows: Iterable<T>, project: (row: T) => unknown, maxBytes: number): Response {
  const messages: string[] = [];
  let size = 15; // The JSON wrapper: {"messages":[]}
  for (const row of rows) {
    const encoded = JSON.stringify(project(row));
    const bytes = encoder.encode(encoded).byteLength + (messages.length ? 1 : 0);
    if (size + bytes > maxBytes) break;
    messages.push(encoded);
    size += bytes;
  }
  return new Response(`{"messages":[${messages.join(',')}]}`, {
    headers: { ...RESPONSE_HEADERS, 'content-type': 'application/json; charset=utf-8' },
  });
}

// Every rejection names itself. A bare "HTTP 500" is what made the 19 September outage
// undiagnosable from the client side, so a platform fault now carries its own cause and
// is written to the Worker log as well.
function failure(error: unknown): Response {
  const messages: Record<number, string> = {
    400: 'Invalid request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found',
    405: 'Method not allowed', 409: 'Conflict', 413: 'Request too large',
    429: 'Request limit exceeded', 500: 'Request failed', 503: 'Service unavailable',
  };
  if (error instanceof HttpError) {
    const body: Record<string, unknown> = { error: messages[error.status] ?? 'Request failed' };
    if (error.code !== undefined) body.code = error.code;
    if (error.retryAfter !== undefined) body.retryAfterSeconds = error.retryAfter;
    const headers: Record<string, string> = error.retryAfter === undefined ? {} : { 'retry-after': String(error.retryAfter) };
    return json(body, error.status, headers);
  }
  const detail = error instanceof Error ? error.message : String(error);
  console.error('agentnet: unhandled failure', detail);
  if (STORAGE_LIMIT_PATTERN.test(detail)) {
    const retryAfter = untilReset(Date.now());
    return json({
      error: messages[503], code: 'storage-limit', detail: detail.slice(0, 300), retryAfterSeconds: retryAfter,
    }, 503, { 'retry-after': String(retryAfter) });
  }
  return json({ error: messages[500], code: 'internal' }, 500);
}

function objectBody(raw: string): Record<string, unknown> {
  try { return record(JSON.parse(raw)); } catch { throw new HttpError(400); }
}

function fields(body: Record<string, unknown>, expected: string[]): void {
  requireValue(Object.keys(body).sort().join(',') === expected.sort().join(','));
}

function optionalFields(body: Record<string, unknown>, allowed: string[]): void {
  requireValue(Object.keys(body).every(key => allowed.includes(key)));
}

function inboxPage(rows: InboxRow[]): Response {
  return messagePage(rows, row => ({
    message: JSON.parse(row.message) as Message,
    sender: JSON.parse(row.identity) as PublicIdentity,
    senderName: row.name,
  }), 1024 * 1024);
}

function identityId(value: unknown): string {
  requireValue(typeof value === 'string' && ID_PATTERN.test(value));
  return value;
}

function bearer(request: Request): string {
  const authorization = request.headers.get('authorization');
  requireValue(typeof authorization === 'string' && authorization.startsWith('Bearer ') && authorization.length <= 4096 + 7, 401);
  const token = authorization.slice(7);
  requireValue(token.length > 0 && token.length <= 4096 && !/\s/.test(token), 401);
  return token;
}

async function boundedBody(request: Request): Promise<string> {
  const length = request.headers.get('content-length');
  if (length !== null) {
    requireValue(/^\d+$/.test(length));
    requireValue(Number(length) <= MAX_REQUEST_BYTES, 413);
  }
  if (!request.body) return '';
  const reader = request.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const chunks: string[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireValue(size <= MAX_REQUEST_BYTES, 413);
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join('');
  } catch (error) {
    void reader.cancel().catch(() => undefined);
    if (error instanceof HttpError) throw error;
    throw new HttpError(400);
  } finally {
    reader.releaseLock();
  }
}


export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      requireValue(!url.search && !url.hash);
      if (url.pathname.startsWith('/v1/')) {
        requireValue(request.method === 'POST', 405);
        requireValue(API_PATHS[url.pathname] === true, 404);
        bearer(request);
        // Preserve the original external URL: JWT audiences never trust forwarded headers.
        return await env.NETWORK.getByName('network').fetch(request);
      }
      requireValue(request.method === 'GET' || request.method === 'HEAD', 405);
      if (url.pathname === '/healthz') return json({ status: 'ok' });
      if (url.pathname === '/') {
        return new Response(request.method === 'HEAD' ? null : 'AgentNet private agent messaging\n\n/about.md\n/install.sh\n/agentnet.mjs\n/agentnet.sha256\n/healthz\n', {
          headers: { ...RESPONSE_HEADERS, 'content-type': 'text/plain; charset=utf-8' },
        });
      }
      if (ASSET_PATHS[url.pathname] === true) {
        if (url.pathname === '/about.md') url.pathname = '/about.txt';
        const asset = await env.ASSETS.fetch(new Request(url, request));
        const response = new Response(asset.body, asset);
        response.headers.set('x-content-type-options', 'nosniff');
        return response;
      }
      throw new HttpError(404);
    } catch (error) { return failure(error); }
  },
} satisfies ExportedHandler<Env>;

export class Network extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private adminIdentity: PublicIdentity | undefined;
  // Long poll waiters, in memory only: eviction or a crash just ends a poll early.
  private readonly waiters = new Map<string, Set<() => void>>();
  // Rate windows, in memory: a durable row per request spent 26,000 writes a day against
  // a 100,000-row daily ceiling. An eviction forgives one window and nothing else.
  private readonly hits = new Map<string, number[]>();
  // The last last_seen value actually written for an identity, so a polling agent stops
  // rewriting its own row on every request.
  private readonly lastSeenWritten = new Map<string, number>();
  private lastCleanup = 0;
  // Rows written today as counted here. The platform's own counter is visible only in the
  // dashboard and in an email after the cap has already stopped the service.
  private meter = { day: '', rows: 0, checkpoint: 0, requests: 0 };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS agents (
          id TEXT PRIMARY KEY,
          identity TEXT NOT NULL,
          name TEXT UNIQUE,
          status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
          created_at INTEGER NOT NULL,
          expires_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS agents_expiry ON agents(status, expires_at);
        CREATE TABLE IF NOT EXISTS grants (
          from_id TEXT NOT NULL,
          to_id TEXT NOT NULL,
          PRIMARY KEY (from_id, to_id)
        );
        CREATE TABLE IF NOT EXISTS invitations (
          hash TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS invitations_expiry ON invitations(expires_at);
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          sender TEXT NOT NULL,
          recipient TEXT NOT NULL,
          message TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'acknowledged', 'blocked')),
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS messages_inbox ON messages(recipient, status, created_at, id);
        CREATE INDEX IF NOT EXISTS messages_sender ON messages(sender);
        CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at);
        CREATE TABLE IF NOT EXISTS nonces (
          identity_id TEXT NOT NULL,
          nonce TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          PRIMARY KEY (identity_id, nonce)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS meters (
          day TEXT PRIMARY KEY,
          rows_written INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          time INTEGER NOT NULL,
          action TEXT NOT NULL,
          subject TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
      `);
      this.migrate();
      this.loadMeter(Date.now());
    });
  }

  // Columns are only ever added, and only when absent: stored identities survive a deploy.
  private migrate(): void {
    const additions: [string, string, string][] = [
      ['agents', 'last_seen', 'INTEGER'],
      ['invitations', 'name', 'TEXT'],
      ['invitations', 'auto_approve', 'INTEGER'],
      ['invitations', 'bound_id', 'TEXT'],
    ];
    for (const [table, column, type] of additions) {
      const present = this.sql.exec<{ name: string }>(`PRAGMA table_info(${table})`).toArray().some(row => row.name === column);
      if (!present) this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
    // Rate limiting moved into memory in 0.4.0; the table only costs writes now.
    this.sql.exec('DROP TABLE IF EXISTS rate_events');
    // A replay row used to cost three rows written: the table row, its primary key index
    // and an expiry index. Every authenticated request writes one, so this was most of
    // the 100,000-row daily budget. WITHOUT ROWID and no secondary index costs one row;
    // the expiry sweep reads the table instead, and reads have a 5,000,000-row budget.
    // Nonces live about a minute, so the table is rebuilt rather than copied.
    const shape = this.sql.exec<{ sql: string }>("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'nonces'").toArray()[0]?.sql ?? '';
    if (shape.includes('WITHOUT ROWID')) return;
    this.sql.exec('DROP TABLE IF EXISTS nonces');
    this.sql.exec(`CREATE TABLE nonces (
      identity_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (identity_id, nonce)
    ) WITHOUT ROWID`);
  }

  // Called after the relevant row commits, never while a transaction or lock is held.
  private wake(key: string): void {
    const waiting = this.waiters.get(key);
    if (!waiting) return;
    this.waiters.delete(key);
    for (const resolve of waiting) resolve();
  }

  private async hold(key: string, deadline: number): Promise<void> {
    const waiting = this.waiters.get(key) ?? new Set<() => void>();
    requireValue(waiting.size < MAX_WAITERS, 429);
    this.waiters.set(key, waiting);
    let resolve!: () => void;
    const woken = new Promise<void>(settle => { resolve = () => settle(); });
    waiting.add(resolve);
    // One resolver ends the wait, whether the awaited change landed or the window closed.
    const timer = setTimeout(resolve, Math.max(0, deadline - Date.now()));
    try {
      await woken;
    } finally {
      clearTimeout(timer);
      const current = this.waiters.get(key);
      if (current) {
        current.delete(resolve);
        if (current.size === 0) this.waiters.delete(key);
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      requireValue(!url.search && !url.hash);
      requireValue(request.method === 'POST', 405);
      requireValue(API_PATHS[url.pathname] === true, 404);
      const token = bearer(request);
      // Do not hold the object-wide authentication lock while reading a client stream.
      const raw = await boundedBody(request);
      this.meter.requests += 1;
      const result = await this.ctx.blockConcurrencyWhile(async () => {
        try {
          this.ctx.storage.transactionSync(() => this.cleanupIfDue(Date.now()));
          const auth = await this.authenticate(token, request.url, raw, url.pathname);
          requireValue(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'application/json');
          const body = objectBody(raw);
          return await this.dispatch(url.pathname, body, auth);
        } catch (error) { return failure(error); }
      });
      this.flushMeter();
      if (result instanceof Response) return result;
      // The wait happens after the lock is released and outside every transaction, so
      // other agents keep sending, acknowledging and being administered during a hold.
      // The nonce was already consumed above: waiting never re-authenticates.
      try {
        const deadline = Date.now() + HOLD_WINDOW;
        for (;;) {
          await this.hold(result.key, deadline);
          // A spurious wake (a rename while a status hold waits) re-waits. An expired
          // hold always yields a response, so the deadline bounds this loop.
          const response = result.resume(Date.now() >= deadline);
          if (response) return response;
        }
      } catch (error) { return failure(error); }
    } catch (error) { return failure(error); }
  }

  // Only a pending alarm from a release that still scheduled one reaches this. It sweeps
  // once and does not reschedule: a minutely alarm was 1,440 requests and 1,440 rows a day
  // to delete rows that every read already filters out.
  async alarm(): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const now = Date.now();
      this.ctx.storage.transactionSync(() => {
        this.lastCleanup = now;
        this.cleanup(now);
      });
      this.flushMeter();
    });
  }

  // Expired rows are excluded by every read that matters, so sweeping is housekeeping.
  // Running it per request cost six write statements per request; ten minutes is enough.
  private cleanupIfDue(now: number): void {
    if (now - this.lastCleanup < CLEANUP_INTERVAL) return;
    this.lastCleanup = now;
    this.cleanup(now);
  }

  private cleanup(now: number): void {
    // Revocation is permanent, including pending enrollment that has timed out.
    this.mutate("UPDATE agents SET status = 'revoked', expires_at = NULL WHERE status = 'pending' AND expires_at <= ?", now);
    this.mutate('DELETE FROM invitations WHERE expires_at <= ?', now);
    this.mutate('DELETE FROM messages WHERE expires_at <= ?', now);
    this.mutate('DELETE FROM nonces WHERE expires_at <= ?', now);
    this.mutate('DELETE FROM audit WHERE time <= ?', now - AUDIT_TTL);
  }

  // Every write goes through here. Rows written is the cap that stopped this service on
  // 19 September, and until now nothing inside the network could see the number.
  private mutate<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: (string | number | null)[]): T[] {
    const cursor = this.sql.exec<T>(query, ...bindings);
    const rows = cursor.toArray();
    const day = new Date().toISOString().slice(0, 10);
    if (day !== this.meter.day) this.meter = { day, rows: 0, checkpoint: 0, requests: this.meter.requests };
    // Counted before the surrounding transaction commits, so a rollback overstates usage.
    // Overstating is the safe direction: the brake trips early, never late.
    this.meter.rows += cursor.rowsWritten;
    return rows;
  }

  private loadMeter(now: number): void {
    const day = new Date(now).toISOString().slice(0, 10);
    const stored = this.sql.exec<{ rows_written: number }>('SELECT rows_written FROM meters WHERE day = ?', day).toArray()[0]?.rows_written ?? 0;
    this.meter = { day, rows: stored, checkpoint: stored, requests: 0 };
    this.sql.exec('DELETE FROM meters WHERE day <> ?', day);
  }

  // One checkpoint row per METER_FLUSH rows keeps the gauge across an eviction without
  // becoming a significant part of what it measures.
  private flushMeter(): void {
    if (this.meter.rows - this.meter.checkpoint < METER_FLUSH) return;
    const { day, rows } = this.meter;
    this.mutate(
      'INSERT INTO meters (day, rows_written) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET rows_written = excluded.rows_written',
      day, rows,
    );
    this.meter.checkpoint = this.meter.rows;
  }

  private rowsLimit(): number {
    const configured = Number(this.env.ROWS_WRITTEN_LIMIT);
    return Number.isFinite(configured) && configured >= 0 && this.env.ROWS_WRITTEN_LIMIT !== undefined
      ? configured : DEFAULT_ROWS_WRITTEN_LIMIT;
  }

  // Near the daily ceiling the object stops spending writes on work that can wait. A send
  // is retryable and a long poll is a convenience; delivery, acknowledgment and
  // administration are what an operator needs in the last hour before a reset.
  private brake(path: string, wait: boolean): void {
    const limit = this.rowsLimit();
    if (limit === 0 || this.meter.rows < limit * BRAKE_SHARE) return;
    if (!wait && path !== '/v1/send' && path !== '/v1/enroll' && path !== '/v1/admin/invite') return;
    throw new HttpError(503, 'storage-brake', untilReset(Date.now()));
  }

  private agent(id: string): AgentRow | undefined {
    return this.sql.exec<AgentRow>('SELECT * FROM agents WHERE id = ?', id).toArray()[0];
  }

  private active(id: string): AgentRow {
    const agent = this.agent(id);
    requireValue(agent?.status === 'active', 403);
    return agent;
  }

  private permitted(from: string, to: string): void {
    this.active(from);
    this.active(to);
    requireValue(this.sql.exec('SELECT 1 FROM grants WHERE from_id = ? AND to_id = ?', from, to).toArray().length === 1, 403);
  }

  private count(query: string, ...bindings: (string | number)[]): number {
    return this.sql.exec<{ count: number }>(query, ...bindings).one().count;
  }

  private audit(action: string, subject: string, now = Date.now()): void {
    this.mutate('INSERT INTO audit (time, action, subject) VALUES (?, ?, ?)', now, action, subject);
    this.mutate('DELETE FROM audit WHERE sequence NOT IN (SELECT sequence FROM audit ORDER BY sequence DESC LIMIT 1000)');
  }

  // In memory on purpose: see the comment on `hits`. The window is per object instance,
  // so an eviction resets it; the cost of that is one extra burst, not a durable row.
  private rate(scope: string, limit: number): void {
    const now = Date.now();
    const window = (this.hits.get(scope) ?? []).filter(at => at > now - MINUTE);
    requireValue(window.length < limit, 429, 'rate');
    window.push(now);
    this.hits.set(scope, window);
    if (this.hits.size <= 1024) return;
    for (const [key, times] of this.hits) {
      if (times[times.length - 1] <= now - MINUTE) this.hits.delete(key);
    }
  }

  private async admin(): Promise<PublicIdentity> {
    if (this.adminIdentity) return this.adminIdentity;
    try {
      requireValue(typeof this.env.ADMIN_IDENTITY === 'string', 503);
      this.adminIdentity = await validatePublicIdentity(JSON.parse(this.env.ADMIN_IDENTITY));
      return this.adminIdentity;
    } catch { throw new HttpError(503); }
  }

  private async authenticate(token: string, url: string, raw: string, path: string): Promise<Authenticated> {
    const admin = await this.admin();
    let issuer: string;
    try {
      const untrusted = decodeJwt(token).iss;
      requireValue(typeof untrusted === 'string' && ID_PATTERN.test(untrusted), 401);
      issuer = untrusted;
    } catch { throw new HttpError(401); }

    const isAdmin = path.startsWith('/v1/admin/');
    let identity: PublicIdentity;
    if (isAdmin) {
      if (issuer === admin.id) {
        identity = admin;
      } else {
        // A known agent may authenticate, but the administrator routes stay denied (403).
        const agent = this.agent(issuer);
        requireValue(agent, 401);
        identity = JSON.parse(agent.identity) as PublicIdentity;
      }
    } else if (path === '/v1/enroll') {
      try { identity = await validatePublicIdentity(objectBody(raw).identity); }
      catch { throw new HttpError(400); }
      requireValue(identity.id === issuer, 401);
    } else {
      const agent = this.agent(issuer);
      requireValue(agent, 401);
      identity = JSON.parse(agent.identity) as PublicIdentity;
    }

    let proof: { nonce: string; expiresAt: number };
    try { proof = await verifyRequest(token, identity, url, raw); }
    catch { throw new HttpError(401); }
    let invitationHash: string | undefined;
    if (path === '/v1/enroll' && !this.agent(identity.id)) {
      // An unknown signer is not authorized until it also holds a valid invitation.
      // Do not let arbitrary self-issued identities allocate replay/rate registry rows.
      const invite = objectBody(raw).invite;
      requireValue(typeof invite === 'string' && INVITE_PATTERN.test(invite), 403);
      invitationHash = await sha256(invite);
      requireValue(this.sql.exec('SELECT 1 FROM invitations WHERE hash = ? AND expires_at > ?', invitationHash, Date.now()).toArray().length === 1, 403);
    }
    this.rate(`request:${identity.id}`, isAdmin && identity.id === admin.id ? 600 : 120);

    // This commit is intentionally separate: even an authorized operation that fails
    // validation, permissions, or quotas burns its nonce and cannot be replayed.
    this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      requireValue(proof.expiresAt > now, 401);
      requireValue(this.sql.exec('SELECT 1 FROM nonces WHERE identity_id = ? AND nonce = ?', identity.id, proof.nonce).toArray().length === 0, 401);
      this.mutate('INSERT INTO nonces (identity_id, nonce, expires_at) VALUES (?, ?, ?)', identity.id, proof.nonce, proof.expiresAt);
      // last_seen is an operator display. Rewriting it on every request of a polling
      // agent spent one row a request for a value nobody reads at that resolution.
      const written = this.lastSeenWritten.get(identity.id);
      if (written === undefined || now - written >= LAST_SEEN_RESOLUTION) {
        this.mutate('UPDATE agents SET last_seen = ? WHERE id = ?', now, identity.id);
        this.lastSeenWritten.set(identity.id, now);
      }
    });

    if (isAdmin) {
      // Authentication succeeded; only the administrator identity passes this gate.
      requireValue(identity.id === admin.id, 403);
    } else {
      requireValue(identity.id !== admin.id, 403);
      if (path !== '/v1/enroll' && path !== '/v1/status') this.active(identity.id);
    }
    // adminKey travels with the request: /v1/status publishes it, and a status hold that
    // resumes outside the lock must not re-read configuration to answer.
    return { identity, admin: isAdmin, adminKey: admin, nonce: proof.nonce, invitationHash };
  }

  private async dispatch(path: string, body: Record<string, unknown>, auth: Authenticated): Promise<Response | Hold> {
    this.brake(path, body.wait === true);
    switch (path) {
      case '/v1/enroll': return this.enroll(body, auth);
      case '/v1/send': return this.send(body, auth);
      case '/v1/admin/invite': return this.invite(body, auth);
      default: {
        // Wake keys are collected inside the transaction and fired once it has committed.
        const woken: string[] = [];
        const result = this.ctx.storage.transactionSync((): Response | Hold => {
          const now = Date.now();
          this.cleanupIfDue(now);
          if (path.startsWith('/v1/admin/')) {
            requireValue(auth.admin, 403);
            return this.adminOperation(path, body, now, woken);
          }
          if (path === '/v1/status') {
            optionalFields(body, ['wait']);
            requireValue(body.wait === undefined || typeof body.wait === 'boolean');
            const agent = this.agent(auth.identity.id);
            requireValue(agent, 403);
            // Pending and revoked identities may wait here: status is the only endpoint
            // they can call, so approval becomes observable without polling.
            if (body.wait === true) {
              const before = agent.status;
              return { key: `status:${agent.id}`, resume: expired => this.statusChange(agent.id, before, auth.adminKey, expired) };
            }
            return this.status(agent, auth.adminKey, now);
          }
          this.active(auth.identity.id);
          switch (path) {
            case '/v1/peers': {
              fields(body, []);
              // The reverse grant is joined in, so a caller knows whether a reply can return.
              const peers = this.sql.exec<{ name: string; identity: string; inbound: number }>(`
                SELECT a.name, a.identity, (r.to_id IS NOT NULL) AS inbound FROM grants g
                JOIN agents a ON a.id = g.to_id
                LEFT JOIN grants r ON r.from_id = g.to_id AND r.to_id = g.from_id
                WHERE g.from_id = ? AND a.status = 'active' ORDER BY a.name
              `, auth.identity.id).toArray().map(peer => ({
                name: peer.name, identity: JSON.parse(peer.identity) as PublicIdentity, inbound: peer.inbound === 1,
              }));
              return json({ peers });
            }
            case '/v1/inbox': {
              optionalFields(body, ['wait']);
              requireValue(body.wait === undefined || typeof body.wait === 'boolean');
              const rows = this.inboxRows(auth.identity.id, now);
              if (rows.length === 0 && body.wait === true) {
                const id = auth.identity.id;
                return { key: `inbox:${id}`, resume: () => this.inbox(id) };
              }
              return inboxPage(rows);
            }
            case '/v1/ack': {
              fields(body, ['ids']);
              requireValue(Array.isArray(body.ids) && body.ids.length <= 100 && body.ids.every(id => typeof id === 'string' && UUID_PATTERN.test(id)));
              let acknowledged = 0;
              for (const id of new Set(body.ids as string[])) {
                acknowledged += this.mutate("UPDATE messages SET status = 'acknowledged' WHERE id = ? AND recipient = ? AND status = 'pending' RETURNING id", id, auth.identity.id).length;
              }
              return json({ acknowledged });
            }
            default: throw new HttpError(404);
          }
        });
        for (const key of woken) this.wake(key);
        return result;
      }
    }
  }

  private inboxRows(id: string, now: number): InboxRow[] {
    return this.sql.exec<InboxRow>(`
      SELECT m.message, a.identity, a.name FROM messages m
      JOIN agents a ON a.id = m.sender AND a.status = 'active'
      JOIN grants g ON g.from_id = m.sender AND g.to_id = m.recipient
      WHERE m.recipient = ? AND m.status = 'pending' AND m.expires_at > ?
      ORDER BY m.created_at, m.id LIMIT 20
    `, id, now).toArray();
  }

  // Second read of a long poll: revocation and grant changes during the wait still apply.
  private inbox(id: string): Response {
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      this.active(id);
      return inboxPage(this.inboxRows(id, now));
    });
  }

  private status(agent: AgentRow, adminKey: PublicIdentity, now: number): Response {
    return json({ id: agent.id, status: agent.status, name: agent.name, serverTime: now, adminKey });
  }

  // Second read of a status long poll: it resolves only once the stored status differs
  // from the one this request authenticated against, so a rename cannot end the wait.
  private statusChange(id: string, before: AgentRow['status'], adminKey: PublicIdentity, expired: boolean): Response | null {
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      const agent = this.agent(id);
      requireValue(agent, 403);
      if (!expired && agent.status === before) return null;
      return this.status(agent, adminKey, now);
    });
  }

  private pendingRows(now: number): AgentRow[] {
    return this.sql.exec<AgentRow>("SELECT * FROM agents WHERE status = 'pending' AND expires_at > ? ORDER BY created_at, id", now).toArray();
  }

  private pendingPage(agents: AgentRow[]): Response {
    return json({ agents: agents.map(agent => ({ identity: JSON.parse(agent.identity) as PublicIdentity, createdAt: agent.created_at })) });
  }

  // Second read of a pending long poll: enrollments committed during the wait are included.
  private pending(): Response {
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      return this.pendingPage(this.pendingRows(now));
    });
  }

  private enroll(body: Record<string, unknown>, auth: Authenticated): Response {
    fields(body, ['identity', 'invite']);
    requireValue(typeof body.invite === 'string' && INVITE_PATTERN.test(body.invite));
    let requested = false;
    const response = this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      requireValue(!auth.admin, 403);
      requireValue(!this.agent(auth.identity.id), 409);
      const hash = auth.invitationHash;
      requireValue(typeof hash === 'string', 403);
      const invitation = this.sql.exec<InvitationRow>('SELECT hash, expires_at, name, auto_approve, bound_id FROM invitations WHERE hash = ? AND expires_at > ?', hash, now).toArray()[0];
      requireValue(invitation, 403);
      // A bound invitation belongs to one fingerprint; legacy rows carry no binding.
      // Refusing before the DELETE rolls back, so the intended holder can still enroll.
      requireValue(typeof invitation.bound_id !== 'string' || invitation.bound_id === auth.identity.id, 403);
      requireValue(this.count('SELECT COUNT(*) AS count FROM agents') < MAX_IDENTITIES, 429);
      const reserved = invitation.auto_approve === 1 && typeof invitation.name === 'string' && NAME_PATTERN.test(invitation.name) ? invitation.name : null;
      if (reserved === null) {
        requireValue(this.count("SELECT COUNT(*) AS count FROM agents WHERE status = 'pending'") < 100, 429);
      } else {
        // The reserved name was taken after the invitation was issued: refuse, and roll
        // back before the invitation is consumed so the administrator can reissue a name.
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', reserved).toArray().length === 0, 409);
      }
      this.mutate('DELETE FROM invitations WHERE hash = ?', hash);
      this.mutate(
        'INSERT INTO agents (id, identity, name, status, created_at, expires_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)',
        auth.identity.id, JSON.stringify(auth.identity), reserved, reserved === null ? 'pending' : 'active',
        now, reserved === null ? now + PENDING_TTL : null, now,
      );
      this.audit('enroll', auth.identity.id, now);
      if (reserved === null) {
        requested = true;
        return json({ id: auth.identity.id, status: 'pending' });
      }
      // Deny by default is unchanged: an auto-approved agent starts with no grants.
      this.audit('approve', auth.identity.id, now);
      return json({ id: auth.identity.id, status: 'active', name: reserved });
    });
    // The row is committed, so a waiting administrator reads the request for itself.
    if (requested) this.wake(PENDING_KEY);
    return response;
  }

  private async invite(body: Record<string, unknown>, auth: Authenticated): Promise<Response> {
    optionalFields(body, ['name', 'autoApprove', 'for']);
    requireValue(auth.admin, 403);
    let name: string | null = null;
    if (body.name !== undefined) {
      requireValue(typeof body.name === 'string' && NAME_PATTERN.test(body.name));
      name = body.name;
    }
    let autoApprove = false;
    if (body.autoApprove !== undefined) {
      requireValue(typeof body.autoApprove === 'boolean');
      autoApprove = body.autoApprove;
    }
    // A bound invitation names the exact fingerprint allowed to consume it.
    const bound = body.for === undefined ? null : identityId(body.for);
    // An invitation that approves itself must carry the name it will claim.
    requireValue(!autoApprove || name !== null);
    this.rate(`invite:${auth.identity.id}`, 10);
    const invite = base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
    const hash = await sha256(invite);
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      const invitations = this.count('SELECT COUNT(*) AS count FROM invitations');
      const pending = this.count("SELECT COUNT(*) AS count FROM agents WHERE status = 'pending'");
      requireValue(invitations + pending < 100, 429);
      requireValue(this.count('SELECT COUNT(*) AS count FROM agents') + invitations < MAX_IDENTITIES, 429);
      if (name !== null) {
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', name).toArray().length === 0, 409);
        requireValue(this.sql.exec('SELECT 1 FROM invitations WHERE name = ? AND expires_at > ?', name, now).toArray().length === 0, 409);
      }
      const expiresAt = now + INVITE_TTL;
      // Only the invitation digest is stored; the token itself never reaches storage.
      this.mutate('INSERT INTO invitations (hash, expires_at, name, auto_approve, bound_id) VALUES (?, ?, ?, ?, ?)', hash, expiresAt, name, autoApprove ? 1 : 0, bound);
      this.audit('invite', auth.identity.id, now);
      return json({ invite, expiresAt, autoApprove, name, for: bound });
    });
  }

  private send(body: Record<string, unknown>, auth: Authenticated): Response {
    fields(body, ['message']);
    this.active(auth.identity.id);
    this.rate(`send:${auth.identity.id}`, 60);
    let stored: string | undefined;
    const response = this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanupIfDue(now);
      let message: Message;
      try {
        const recipient = identityId(record(body.message).to);
        message = validateMessage(body.message, auth.identity.id, recipient, now);
      } catch { throw new HttpError(400); }
      // No await may separate this permission check from storage or response release.
      this.permitted(auth.identity.id, message.to);
      const { id, from, to, createdAt, expiresAt, kind, text } = message;
      const encoded = JSON.stringify({ id, from, to, createdAt, expiresAt, kind, text });
      const previous = this.sql.exec<{ sender: string; recipient: string; message: string }>('SELECT sender, recipient, message FROM messages WHERE id = ?', id).toArray()[0];
      // recipientPending is read in the same transaction as the insert, so the depth a
      // sender is told is exactly the one its own message produced: a backpressure signal.
      if (previous) {
        requireValue(previous.sender === from && previous.recipient === to && previous.message === encoded, 409);
        return json({ id, duplicate: true, recipientPending: this.pendingFor(to) });
      }
      requireValue(this.pendingFor(to) < 100, 429);
      requireValue(this.count('SELECT COUNT(*) AS count FROM messages') < 10_000, 429);
      // Retained acknowledged/blocked rows are also dedup receipts until original expiry.
      this.mutate("INSERT INTO messages (id, sender, recipient, message, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)", id, from, to, encoded, now, expiresAt);
      stored = to;
      return json({ id, duplicate: false, recipientPending: this.pendingFor(to) });
    });
    // The row is committed, so a woken poll re-reads it under the recipient's own grants.
    if (stored !== undefined) this.wake(`inbox:${stored}`);
    return response;
  }

  private pendingFor(recipient: string): number {
    return this.count("SELECT COUNT(*) AS count FROM messages WHERE recipient = ? AND status = 'pending'", recipient);
  }

  // Administration accepts a full identity id or a unique hexadecimal prefix of one.
  private resolveId(value: unknown): string {
    requireValue(typeof value === 'string' && ID_PREFIX_PATTERN.test(value));
    if (ID_PATTERN.test(value)) return value;
    const matches = this.sql.exec<{ id: string }>('SELECT id FROM agents WHERE substr(id, 1, ?) = ? LIMIT 2', value.length, value).toArray();
    requireValue(matches.length > 0, 404);
    requireValue(matches.length === 1, 409);
    return matches[0].id;
  }

  private peerIds(value: unknown, exclude: string): string[] {
    if (value === undefined) return [];
    requireValue(Array.isArray(value) && value.length <= 16);
    const ids = new Set((value as unknown[]).map(entry => this.resolveId(entry)));
    ids.delete(exclude);
    for (const id of ids) this.active(id);
    return [...ids];
  }

  private link(from: string, to: string): void {
    this.mutate('INSERT OR IGNORE INTO grants (from_id, to_id) VALUES (?, ?)', from, to);
    this.mutate('INSERT OR IGNORE INTO grants (from_id, to_id) VALUES (?, ?)', to, from);
  }

  private adminOperation(path: string, body: Record<string, unknown>, now: number, woken: string[]): Response | Hold {
    switch (path) {
      case '/v1/admin/pending': {
        optionalFields(body, ['wait']);
        requireValue(body.wait === undefined || typeof body.wait === 'boolean');
        const agents = this.pendingRows(now);
        // The enroll path resolves this wait once a pending row has committed.
        if (agents.length === 0 && body.wait === true) return { key: PENDING_KEY, resume: () => this.pending() };
        return this.pendingPage(agents);
      }
      case '/v1/admin/agents': {
        fields(body, []);
        const agents = this.sql.exec<AgentRow>('SELECT * FROM agents ORDER BY created_at, id').toArray();
        return json({ agents: agents.map(agent => ({ identity: JSON.parse(agent.identity) as PublicIdentity, name: agent.name, status: agent.status, createdAt: agent.created_at })) });
      }
      case '/v1/admin/peers': {
        fields(body, ['id']);
        const id = this.resolveId(body.id);
        this.active(id);
        // Same query shape as /v1/peers, parameterized by the administrator-supplied identity.
        const peers = this.sql.exec<{ name: string; identity: string; inbound: number }>(`
          SELECT a.name, a.identity, (r.to_id IS NOT NULL) AS inbound FROM grants g
          JOIN agents a ON a.id = g.to_id
          LEFT JOIN grants r ON r.from_id = g.to_id AND r.to_id = g.from_id
          WHERE g.from_id = ? AND a.status = 'active' ORDER BY a.name
        `, id).toArray().map(peer => ({
          name: peer.name, identity: JSON.parse(peer.identity) as PublicIdentity, inbound: peer.inbound === 1,
        }));
        return json({ peers });
      }
      case '/v1/admin/audit': {
        fields(body, []);
        const events = this.sql.exec<{ time: number; action: string; subject: string }>('SELECT time, action, subject FROM audit ORDER BY sequence DESC LIMIT 1000').toArray();
        return json({ events });
      }
      case '/v1/admin/messages': {
        optionalFields(body, ['agent']);
        const agent = body.agent === undefined ? null : this.resolveId(body.agent);
        const rows = agent === null
          ? this.sql.exec<{ message: string; status: string }>('SELECT message, status FROM messages ORDER BY created_at DESC, id DESC LIMIT 100')
          : this.sql.exec<{ message: string; status: string }>('SELECT message, status FROM messages WHERE sender = ? OR recipient = ? ORDER BY created_at DESC, id DESC LIMIT 100', agent, agent);
        return messagePage(rows, row => ({ message: JSON.parse(row.message) as Message, status: row.status }), 2 * 1024 * 1024);
      }
      case '/v1/admin/approve': {
        optionalFields(body, ['id', 'name', 'grantWith']);
        const id = this.resolveId(body.id);
        requireValue(typeof body.name === 'string' && NAME_PATTERN.test(body.name));
        const agent = this.agent(id);
        requireValue(agent?.status === 'pending' && agent.expires_at !== null && agent.expires_at > now, 409);
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', body.name).toArray().length === 0, 409);
        // Resolved after the approval itself is known to be valid, so a bad peer list
        // cannot mask a stale or already-approved enrollment.
        const peers = this.peerIds(body.grantWith, id);
        this.mutate("UPDATE agents SET name = ?, status = 'active', expires_at = NULL WHERE id = ?", body.name, id);
        this.audit('approve', id, now);
        woken.push(`status:${id}`);
        for (const peer of peers) {
          this.link(id, peer);
          this.audit('grant', `${id}:${peer}`, now);
          this.audit('grant', `${peer}:${id}`, now);
        }
        return json({ id, status: 'active', name: body.name, mutualGrants: peers.length });
      }
      case '/v1/admin/rename': {
        fields(body, ['id', 'name']);
        const id = this.resolveId(body.id);
        requireValue(typeof body.name === 'string' && NAME_PATTERN.test(body.name));
        requireValue(this.agent(id)?.status === 'active', 409);
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', body.name).toArray().length === 0, 409);
        this.mutate('UPDATE agents SET name = ? WHERE id = ?', body.name, id);
        this.audit('rename', id, now);
        woken.push(`status:${id}`);
        return json({ id, name: body.name });
      }
      case '/v1/admin/revoke': {
        fields(body, ['id']);
        const id = this.resolveId(body.id);
        requireValue(this.agent(id), 404);
        this.mutate("UPDATE agents SET status = 'revoked', expires_at = NULL WHERE id = ?", id);
        this.mutate('DELETE FROM grants WHERE from_id = ? OR to_id = ?', id, id);
        this.mutate("UPDATE messages SET status = 'blocked' WHERE status = 'pending' AND (sender = ? OR recipient = ?)", id, id);
        this.audit('revoke', id, now);
        woken.push(`status:${id}`);
        return json({ id, status: 'revoked' });
      }
      case '/v1/admin/grant': {
        fields(body, ['from', 'to', 'allow']);
        const from = this.resolveId(body.from);
        const to = this.resolveId(body.to);
        requireValue(typeof body.allow === 'boolean');
        this.active(from);
        this.active(to);
        if (body.allow) {
          this.mutate('INSERT OR IGNORE INTO grants (from_id, to_id) VALUES (?, ?)', from, to);
        } else {
          this.mutate('DELETE FROM grants WHERE from_id = ? AND to_id = ?', from, to);
          this.mutate("UPDATE messages SET status = 'blocked' WHERE status = 'pending' AND sender = ? AND recipient = ?", from, to);
        }
        this.audit(body.allow ? 'grant' : 'ungrant', `${from}:${to}`, now);
        return json({ from, to, allow: body.allow });
      }
      case '/v1/admin/mesh': {
        fields(body, ['ids']);
        requireValue(Array.isArray(body.ids) && body.ids.length >= 2 && body.ids.length <= 16);
        const ids = new Set((body.ids as unknown[]).map(entry => this.resolveId(entry)));
        requireValue(ids.size >= 2);
        for (const id of ids) this.active(id);
        const list = [...ids];
        let edges = 0;
        for (let i = 0; i < list.length; i += 1) {
          for (let j = i + 1; j < list.length; j += 1) {
            this.link(list[i], list[j]);
            edges += 2;
            this.audit('grant', `${list[i]}:${list[j]}`, now);
            this.audit('grant', `${list[j]}:${list[i]}`, now);
          }
        }
        return json({ edges });
      }
      case '/v1/admin/status': {
        fields(body, []);
        const agents = this.sql.exec<{ id: string; name: string | null; status: string; last_seen: number | null; unread: number }>(`
          SELECT a.id, a.name, a.status, a.last_seen,
            (SELECT COUNT(*) FROM messages m WHERE m.recipient = a.id AND m.status = 'pending' AND m.expires_at > ?) AS unread
          FROM agents a ORDER BY a.name, a.id LIMIT 1000
        `, now).toArray();
        const totals = this.sql.exec<{ active: number; pending: number; revoked: number; messages: number; pendingMessages: number }>(`
          SELECT
            (SELECT COUNT(*) FROM agents WHERE status = 'active') AS active,
            (SELECT COUNT(*) FROM agents WHERE status = 'pending') AS pending,
            (SELECT COUNT(*) FROM agents WHERE status = 'revoked') AS revoked,
            (SELECT COUNT(*) FROM messages) AS messages,
            (SELECT COUNT(*) FROM messages WHERE status = 'pending' AND expires_at > ?) AS pendingMessages
        `, now).one();
        const limit = this.rowsLimit();
        return json({
          agents: agents.map(agent => ({ id: agent.id, name: agent.name, status: agent.status, unread: agent.unread, lastSeen: agent.last_seen })),
          totals,
          // The free tier's own counters are invisible from inside the network. This is
          // what this object has spent today, so an operator can act before a cap does.
          usage: {
            day: this.meter.day,
            rowsWritten: this.meter.rows,
            rowsWrittenLimit: limit,
            percent: limit === 0 ? 0 : Math.round((this.meter.rows / limit) * 1000) / 10,
            requests: this.meter.requests,
            brakeAt: limit === 0 ? 0 : Math.floor(limit * BRAKE_SHARE),
            resetInSeconds: untilReset(now),
          },
        });
      }
      default: throw new HttpError(404);
    }
  }
}
