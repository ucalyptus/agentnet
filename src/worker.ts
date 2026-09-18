import { DurableObject } from 'cloudflare:workers';
import { base64url, decodeJwt } from 'jose';
import {
  ID_PATTERN, MAX_REQUEST_BYTES, UUID_PATTERN,
  record, sha256, validateMessage, validatePublicIdentity, verifyRequest,
  type Message, type PublicIdentity,
} from './protocol.ts';

export interface Env {
  NETWORK: DurableObjectNamespace<Network>;
  ASSETS: Fetcher;
  ADMIN_IDENTITY?: string;
}

const MINUTE = 60_000;
const PENDING_TTL = 24 * 60 * MINUTE;
const INVITE_TTL = 60 * MINUTE;
const AUDIT_TTL = 30 * 24 * 60 * MINUTE;
const API_PATHS: Record<string, true> = {
  '/v1/enroll': true, '/v1/status': true, '/v1/peers': true,
  '/v1/send': true, '/v1/inbox': true, '/v1/ack': true,
  '/v1/admin/invite': true, '/v1/admin/pending': true, '/v1/admin/approve': true, '/v1/admin/rename': true,
  '/v1/admin/revoke': true, '/v1/admin/grant': true, '/v1/admin/agents': true,
  '/v1/admin/audit': true, '/v1/admin/messages': true,
};
const ASSET_PATHS: Record<string, true> = {
  '/about.md': true, '/about.txt': true, '/agentnet.mjs': true,
  '/agentnet.sha256': true, '/install.sh': true,
};
const NAME_PATTERN = /^[a-z][a-z0-9-]{0,47}$/;
const INVITE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const RESPONSE_HEADERS = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const encoder = new TextEncoder();

type AgentRow = {
  id: string;
  identity: string;
  name: string | null;
  status: 'pending' | 'active' | 'revoked';
  created_at: number;
  expires_at: number | null;
};
type Authenticated = {
  identity: PublicIdentity;
  admin: boolean;
  nonce: string;
  invitationHash: string | undefined;
};

class HttpError extends Error {
  constructor(readonly status: number) { super('Request rejected'); }
}

function requireValue(condition: unknown, status = 400): asserts condition {
  if (!condition) throw new HttpError(status);
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: RESPONSE_HEADERS });
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

function failure(error: unknown): Response {
  const status = error instanceof HttpError ? error.status : 500;
  const messages: Record<number, string> = {
    400: 'Invalid request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found',
    405: 'Method not allowed', 409: 'Conflict', 413: 'Request too large',
    429: 'Request limit exceeded', 500: 'Request failed', 503: 'Service unavailable',
  };
  return json({ error: messages[status] ?? 'Request failed' }, status);
}

function objectBody(raw: string): Record<string, unknown> {
  try { return record(JSON.parse(raw)); } catch { throw new HttpError(400); }
}

function fields(body: Record<string, unknown>, expected: string[]): void {
  requireValue(Object.keys(body).sort().join(',') === expected.sort().join(','));
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
        );
        CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(expires_at);
        CREATE TABLE IF NOT EXISTS rate_events (
          scope TEXT NOT NULL,
          nonce TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (scope, nonce)
        );
        CREATE INDEX IF NOT EXISTS rate_events_time ON rate_events(created_at);
        CREATE TABLE IF NOT EXISTS audit (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          time INTEGER NOT NULL,
          action TEXT NOT NULL,
          subject TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
      `);
      this.ctx.storage.transactionSync(() => this.cleanup(Date.now()));
      await this.ctx.storage.setAlarm(Date.now() + MINUTE);
    });
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
      return await this.ctx.blockConcurrencyWhile(async () => {
        try {
          this.ctx.storage.transactionSync(() => this.cleanup(Date.now()));
          const auth = await this.authenticate(token, request.url, raw, url.pathname);
          requireValue(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'application/json');
          const body = objectBody(raw);
          return await this.dispatch(url.pathname, body, auth);
        } catch (error) { return failure(error); }
      });
    } catch (error) { return failure(error); }
  }

  async alarm(): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.transactionSync(() => this.cleanup(Date.now()));
      await this.ctx.storage.setAlarm(Date.now() + MINUTE);
    });
  }

  private cleanup(now: number): void {
    // Revocation is permanent, including pending enrollment that has timed out.
    this.sql.exec("UPDATE agents SET status = 'revoked', expires_at = NULL WHERE status = 'pending' AND expires_at <= ?", now);
    this.sql.exec('DELETE FROM invitations WHERE expires_at <= ?', now);
    this.sql.exec('DELETE FROM messages WHERE expires_at <= ?', now);
    this.sql.exec('DELETE FROM nonces WHERE expires_at <= ?', now);
    this.sql.exec('DELETE FROM rate_events WHERE created_at <= ?', now - MINUTE);
    this.sql.exec('DELETE FROM audit WHERE time <= ?', now - AUDIT_TTL);
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
    this.sql.exec('INSERT INTO audit (time, action, subject) VALUES (?, ?, ?)', now, action, subject);
    this.sql.exec('DELETE FROM audit WHERE sequence NOT IN (SELECT sequence FROM audit ORDER BY sequence DESC LIMIT 1000)');
  }

  private rate(scope: string, nonce: string, limit: number): void {
    this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      requireValue(this.count('SELECT COUNT(*) AS count FROM rate_events WHERE scope = ? AND created_at > ?', scope, now - MINUTE) < limit, 429);
      this.sql.exec('INSERT INTO rate_events (scope, nonce, created_at) VALUES (?, ?, ?)', scope, nonce, now);
    });
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
    this.rate(`request:${identity.id}`, crypto.randomUUID(), isAdmin && identity.id === admin.id ? 600 : 120);

    // This commit is intentionally separate: even an authorized operation that fails
    // validation, permissions, or quotas burns its nonce and cannot be replayed.
    this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanup(now);
      requireValue(proof.expiresAt > now, 401);
      requireValue(this.sql.exec('SELECT 1 FROM nonces WHERE identity_id = ? AND nonce = ?', identity.id, proof.nonce).toArray().length === 0, 401);
      this.sql.exec('INSERT INTO nonces (identity_id, nonce, expires_at) VALUES (?, ?, ?)', identity.id, proof.nonce, proof.expiresAt);
    });

    if (isAdmin) {
      // Authentication succeeded; only the administrator identity passes this gate.
      requireValue(identity.id === admin.id, 403);
    } else {
      requireValue(identity.id !== admin.id, 403);
      if (path !== '/v1/enroll' && path !== '/v1/status') this.active(identity.id);
    }
    return { identity, admin: isAdmin, nonce: proof.nonce, invitationHash };
  }

  private async dispatch(path: string, body: Record<string, unknown>, auth: Authenticated): Promise<Response> {
    switch (path) {
      case '/v1/enroll': return this.enroll(body, auth);
      case '/v1/send': return this.send(body, auth);
      case '/v1/admin/invite': return this.invite(body, auth);
      default:
        return this.ctx.storage.transactionSync(() => {
          const now = Date.now();
          this.cleanup(now);
          if (path.startsWith('/v1/admin/')) {
            requireValue(auth.admin, 403);
            return this.adminOperation(path, body, now);
          }
          if (path === '/v1/status') {
            fields(body, []);
            const agent = this.agent(auth.identity.id);
            requireValue(agent, 403);
            return json({ id: agent.id, status: agent.status, name: agent.name });
          }
          this.active(auth.identity.id);
          switch (path) {
            case '/v1/peers': {
              fields(body, []);
              const peers = this.sql.exec<{ name: string; identity: string }>(`
                SELECT a.name, a.identity FROM grants g JOIN agents a ON a.id = g.to_id
                WHERE g.from_id = ? AND a.status = 'active' ORDER BY a.name
              `, auth.identity.id).toArray().map(peer => ({ name: peer.name, identity: JSON.parse(peer.identity) as PublicIdentity }));
              return json({ peers });
            }
            case '/v1/inbox': {
              fields(body, []);
              const rows = this.sql.exec<{ message: string; identity: string; name: string }>(`
                SELECT m.message, a.identity, a.name FROM messages m
                JOIN agents a ON a.id = m.sender AND a.status = 'active'
                JOIN grants g ON g.from_id = m.sender AND g.to_id = m.recipient
                WHERE m.recipient = ? AND m.status = 'pending' AND m.expires_at > ?
                ORDER BY m.created_at, m.id LIMIT 20
              `, auth.identity.id, now);
              return messagePage(rows, row => ({
                message: JSON.parse(row.message) as Message,
                sender: JSON.parse(row.identity) as PublicIdentity,
                senderName: row.name,
              }), 1024 * 1024);
            }
            case '/v1/ack': {
              fields(body, ['ids']);
              requireValue(Array.isArray(body.ids) && body.ids.length <= 100 && body.ids.every(id => typeof id === 'string' && UUID_PATTERN.test(id)));
              let acknowledged = 0;
              for (const id of new Set(body.ids as string[])) {
                const updated = this.sql.exec("UPDATE messages SET status = 'acknowledged' WHERE id = ? AND recipient = ? AND status = 'pending' RETURNING id", id, auth.identity.id);
                acknowledged += updated.toArray().length;
              }
              return json({ acknowledged });
            }
            default: throw new HttpError(404);
          }
        });
    }
  }

  private enroll(body: Record<string, unknown>, auth: Authenticated): Response {
    fields(body, ['identity', 'invite']);
    requireValue(typeof body.invite === 'string' && INVITE_PATTERN.test(body.invite));
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanup(now);
      requireValue(!auth.admin, 403);
      requireValue(!this.agent(auth.identity.id), 409);
      const hash = auth.invitationHash;
      requireValue(typeof hash === 'string', 403);
      requireValue(this.sql.exec('SELECT 1 FROM invitations WHERE hash = ? AND expires_at > ?', hash, now).toArray().length === 1, 403);
      requireValue(this.count('SELECT COUNT(*) AS count FROM agents') < 1000, 429);
      requireValue(this.count("SELECT COUNT(*) AS count FROM agents WHERE status = 'pending'") < 100, 429);
      this.sql.exec('DELETE FROM invitations WHERE hash = ?', hash);
      this.sql.exec("INSERT INTO agents (id, identity, name, status, created_at, expires_at) VALUES (?, ?, NULL, 'pending', ?, ?)", auth.identity.id, JSON.stringify(auth.identity), now, now + PENDING_TTL);
      this.audit('enroll', auth.identity.id, now);
      return json({ id: auth.identity.id, status: 'pending' });
    });
  }

  private async invite(body: Record<string, unknown>, auth: Authenticated): Promise<Response> {
    fields(body, []);
    requireValue(auth.admin, 403);
    this.rate(`invite:${auth.identity.id}`, auth.nonce, 10);
    const invite = base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
    const hash = await sha256(invite);
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanup(now);
      const invitations = this.count('SELECT COUNT(*) AS count FROM invitations');
      const pending = this.count("SELECT COUNT(*) AS count FROM agents WHERE status = 'pending'");
      requireValue(invitations + pending < 100, 429);
      requireValue(this.count('SELECT COUNT(*) AS count FROM agents') + invitations < 1000, 429);
      const expiresAt = now + INVITE_TTL;
      this.sql.exec('INSERT INTO invitations (hash, expires_at) VALUES (?, ?)', hash, expiresAt);
      this.audit('invite', auth.identity.id, now);
      return json({ invite, expiresAt });
    });
  }

  private send(body: Record<string, unknown>, auth: Authenticated): Response {
    fields(body, ['message']);
    this.active(auth.identity.id);
    this.rate(`send:${auth.identity.id}`, auth.nonce, 60);
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.cleanup(now);
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
      if (previous) {
        requireValue(previous.sender === from && previous.recipient === to && previous.message === encoded, 409);
        return json({ id, duplicate: true });
      }
      requireValue(this.count("SELECT COUNT(*) AS count FROM messages WHERE recipient = ? AND status = 'pending'", to) < 100, 429);
      requireValue(this.count('SELECT COUNT(*) AS count FROM messages') < 10_000, 429);
      // Retained acknowledged/blocked rows are also dedup receipts until original expiry.
      this.sql.exec("INSERT INTO messages (id, sender, recipient, message, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)", id, from, to, encoded, now, expiresAt);
      return json({ id, duplicate: false });
    });
  }

  private adminOperation(path: string, body: Record<string, unknown>, now: number): Response {
    switch (path) {
      case '/v1/admin/pending': {
        fields(body, []);
        const agents = this.sql.exec<AgentRow>("SELECT * FROM agents WHERE status = 'pending' AND expires_at > ? ORDER BY created_at, id", now).toArray();
        return json({ agents: agents.map(agent => ({ identity: JSON.parse(agent.identity) as PublicIdentity, createdAt: agent.created_at })) });
      }
      case '/v1/admin/agents': {
        fields(body, []);
        const agents = this.sql.exec<AgentRow>('SELECT * FROM agents ORDER BY created_at, id').toArray();
        return json({ agents: agents.map(agent => ({ identity: JSON.parse(agent.identity) as PublicIdentity, name: agent.name, status: agent.status, createdAt: agent.created_at })) });
      }
      case '/v1/admin/audit': {
        fields(body, []);
        const events = this.sql.exec<{ time: number; action: string; subject: string }>('SELECT time, action, subject FROM audit ORDER BY sequence DESC LIMIT 1000').toArray();
        return json({ events });
      }
      case '/v1/admin/messages': {
        fields(body, body.agent === undefined ? [] : ['agent']);
        const agent = body.agent === undefined ? null : identityId(body.agent);
        const rows = agent === null
          ? this.sql.exec<{ message: string; status: string }>('SELECT message, status FROM messages ORDER BY created_at DESC, id DESC LIMIT 100')
          : this.sql.exec<{ message: string; status: string }>('SELECT message, status FROM messages WHERE sender = ? OR recipient = ? ORDER BY created_at DESC, id DESC LIMIT 100', agent, agent);
        return messagePage(rows, row => ({ message: JSON.parse(row.message) as Message, status: row.status }), 2 * 1024 * 1024);
      }
      case '/v1/admin/approve': {
        fields(body, ['id', 'name']);
        const id = identityId(body.id);
        requireValue(typeof body.name === 'string' && NAME_PATTERN.test(body.name));
        const agent = this.agent(id);
        requireValue(agent?.status === 'pending' && agent.expires_at !== null && agent.expires_at > now, 409);
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', body.name).toArray().length === 0, 409);
        this.sql.exec("UPDATE agents SET name = ?, status = 'active', expires_at = NULL WHERE id = ?", body.name, id);
        this.audit('approve', id, now);
        return json({ id, status: 'active', name: body.name });
      }
      case '/v1/admin/rename': {
        fields(body, ['id', 'name']);
        const id = identityId(body.id);
        requireValue(typeof body.name === 'string' && NAME_PATTERN.test(body.name));
        requireValue(this.agent(id)?.status === 'active', 409);
        requireValue(this.sql.exec('SELECT 1 FROM agents WHERE name = ?', body.name).toArray().length === 0, 409);
        this.sql.exec('UPDATE agents SET name = ? WHERE id = ?', body.name, id);
        this.audit('rename', id, now);
        return json({ id, name: body.name });
      }
      case '/v1/admin/revoke': {
        fields(body, ['id']);
        const id = identityId(body.id);
        requireValue(this.agent(id), 404);
        this.sql.exec("UPDATE agents SET status = 'revoked', expires_at = NULL WHERE id = ?", id);
        this.sql.exec('DELETE FROM grants WHERE from_id = ? OR to_id = ?', id, id);
        this.sql.exec("UPDATE messages SET status = 'blocked' WHERE status = 'pending' AND (sender = ? OR recipient = ?)", id, id);
        this.audit('revoke', id, now);
        return json({ id, status: 'revoked' });
      }
      case '/v1/admin/grant': {
        fields(body, ['from', 'to', 'allow']);
        const from = identityId(body.from);
        const to = identityId(body.to);
        requireValue(typeof body.allow === 'boolean');
        this.active(from);
        this.active(to);
        if (body.allow) {
          this.sql.exec('INSERT OR IGNORE INTO grants (from_id, to_id) VALUES (?, ?)', from, to);
        } else {
          this.sql.exec('DELETE FROM grants WHERE from_id = ? AND to_id = ?', from, to);
          this.sql.exec("UPDATE messages SET status = 'blocked' WHERE status = 'pending' AND sender = ? AND recipient = ?", from, to);
        }
        this.audit(body.allow ? 'grant' : 'ungrant', `${from}:${to}`, now);
        return json({ from, to, allow: body.allow });
      }
      default: throw new HttpError(404);
    }
  }
}
