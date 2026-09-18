import {
  SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK,
  jwtVerify, type JWK,
} from 'jose';

export const MESSAGE_TTL = 7 * 24 * 60 * 60 * 1000;
export const MAX_TEXT_BYTES = 32 * 1024;
export const MAX_REQUEST_BYTES = 224 * 1024;
export const ID_PATTERN = /^[a-f0-9]{64}$/;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();

export interface PublicIdentity { id: string; signingKey: JWK }
export interface PrivateIdentity { public: PublicIdentity; signingPrivateKey: JWK }
export interface MessageBody { kind: 'message' | 'prompt' | 'instruction'; text: string }
export interface Message extends MessageBody {
  id: string;
  from: string;
  to: string;
  createdAt: number;
  expiresAt: number;
}
export interface Peer { name: string; identity: PublicIdentity }
export interface InboxItem { message: Message; sender: PublicIdentity; senderName: string }

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
export function record(value: unknown): Record<string, unknown> {
  assert(value !== null && typeof value === 'object' && !Array.isArray(value), 'Expected an object');
  return value as Record<string, unknown>;
}
export async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}
async function identityId(signingKey: JWK): Promise<string> {
  return sha256(`agentnet-identity-v1\n${await calculateJwkThumbprint(signingKey)}`);
}
export async function validatePublicIdentity(value: unknown): Promise<PublicIdentity> {
  const identity = record(value);
  assert(Object.keys(identity).sort().join(',') === 'id,signingKey', 'Invalid public identity fields');
  assert(typeof identity.id === 'string' && ID_PATTERN.test(identity.id), 'Invalid identity ID');
  const key = record(identity.signingKey);
  assert(Object.keys(key).sort().join(',') === 'crv,kty,x', 'Only public key coordinates are accepted');
  assert(key.kty === 'OKP' && key.crv === 'Ed25519' && typeof key.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(key.x), 'Invalid Ed25519 public key');
  const signingKey = key as JWK;
  assert(identity.id === await identityId(signingKey), 'Identity fingerprint does not match key');
  await importJWK(signingKey, 'EdDSA');
  return { id: identity.id, signingKey };
}
export async function generateIdentity(): Promise<PrivateIdentity> {
  const signing = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const publicJwk = await exportJWK(signing.publicKey);
  const signingKey: JWK = { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x };
  return {
    public: { id: await identityId(signingKey), signingKey },
    signingPrivateKey: await exportJWK(signing.privateKey),
  };
}
export function serverURL(value: string): string {
  const url = new URL(value);
  assert(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/', 'Server must be a bare origin');
  assert(url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)), 'HTTPS is required outside localhost');
  return url.origin;
}
export async function signRequest(identity: PrivateIdentity, url: string, body: string): Promise<string> {
  const target = new URL(url);
  assert(!target.search && !target.hash, 'Query strings are not supported');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ method: 'POST', path: target.pathname, hash: await sha256(body) })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'agentnet-request+jwt' })
    .setIssuer(identity.public.id).setAudience(target.origin).setJti(crypto.randomUUID())
    .setIssuedAt(now).setExpirationTime(now + 60)
    .sign(await importJWK(identity.signingPrivateKey, 'EdDSA'));
}
export async function verifyRequest(token: string, identity: PublicIdentity, url: string, body: string): Promise<{ nonce: string; expiresAt: number }> {
  const target = new URL(url);
  assert(!target.search && !target.hash, 'Query strings are not supported');
  const { payload } = await jwtVerify(token, await importJWK(identity.signingKey, 'EdDSA'), {
    algorithms: ['EdDSA'], typ: 'agentnet-request+jwt', issuer: identity.id,
    audience: target.origin, requiredClaims: ['iat', 'exp', 'jti'], maxTokenAge: '60s', clockTolerance: 0,
  });
  assert(payload.method === 'POST' && payload.path === target.pathname && payload.hash === await sha256(body), 'Request signature does not match request');
  assert(typeof payload.iat === 'number' && typeof payload.exp === 'number' && payload.exp <= payload.iat + 60, 'Invalid request validity');
  assert(typeof payload.jti === 'string' && UUID_PATTERN.test(payload.jti), 'Invalid request nonce');
  return { nonce: payload.jti, expiresAt: payload.exp * 1000 };
}
export function validateMessageBody(value: unknown): MessageBody {
  const body = record(value);
  assert(Object.keys(body).sort().join(',') === 'kind,text', 'Invalid message body fields');
  assert(['message', 'prompt', 'instruction'].includes(String(body.kind)), 'Invalid message kind');
  assert(typeof body.text === 'string' && encoder.encode(body.text).byteLength > 0 && encoder.encode(body.text).byteLength <= MAX_TEXT_BYTES, 'Message must contain 1 to 32768 UTF-8 bytes');
  return body as unknown as MessageBody;
}
export function createMessage(senderId: string, recipientId: string, body: MessageBody): Message {
  validateMessageBody(body);
  const createdAt = Date.now();
  return { id: crypto.randomUUID(), from: senderId, to: recipientId, createdAt, expiresAt: createdAt + MESSAGE_TTL, ...body };
}
export function validateMessage(value: unknown, senderId: string, recipientId: string, now = Date.now()): Message {
  const m = record(value);
  assert(Object.keys(m).sort().join(',') === 'createdAt,expiresAt,from,id,kind,text,to', 'Invalid message fields');
  assert(typeof m.id === 'string' && UUID_PATTERN.test(m.id), 'Invalid message ID');
  assert(ID_PATTERN.test(senderId) && ID_PATTERN.test(recipientId) && m.from === senderId && m.to === recipientId, 'Message identity mismatch');
  assert(Number.isSafeInteger(m.createdAt) && Number.isSafeInteger(m.expiresAt), 'Invalid message times');
  assert((m.createdAt as number) <= now + 60_000 && (m.expiresAt as number) > now && (m.expiresAt as number) > (m.createdAt as number) && (m.expiresAt as number) <= (m.createdAt as number) + MESSAGE_TTL && (m.expiresAt as number) <= now + MESSAGE_TTL, 'Message is expired or outside validity window');
  validateMessageBody({ kind: m.kind, text: m.text });
  return m as unknown as Message;
}
