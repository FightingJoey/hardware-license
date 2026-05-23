// Crypto primitives. Pure Node built-ins, no native deps.

import {
  createPublicKey,
  createPrivateKey,
  verify as edVerify,
  sign as edSign,
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

import { canonicalJSON } from './canonical';
import {
  EncryptedPayload,
  License,
  Payload,
  Watermark,
} from './types';

/** Parse a PEM file. Throws on any error; never returns null. */
export function loadEd25519Public(pemPath: string): KeyObject {
  const pem = readFileSync(pemPath, 'utf8');
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`expected ed25519 public key, got ${key.asymmetricKeyType}`);
  }
  return key;
}

export function loadEd25519Private(pemPath: string): KeyObject {
  const pem = readFileSync(pemPath, 'utf8');
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`expected ed25519 private key, got ${key.asymmetricKeyType}`);
  }
  return key;
}

export function fingerprintBytes(hex: string): Buffer {
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error('fingerprint must be 64 hex chars');
  }
  return Buffer.from(hex, 'hex');
}

/** HKDF-SHA256(ikm=fpBytes, salt=licenseId, info=info, len=32). */
export function deriveKey(fpBytes: Buffer, licenseId: string, info: string): Buffer {
  const out = hkdfSync('sha256', fpBytes, Buffer.from(licenseId, 'utf8'), Buffer.from(info, 'utf8'), 32);
  // hkdfSync returns ArrayBuffer in older Node typings; cast safely.
  return Buffer.from(out);
}

/** AES-256-GCM seal of the canonical-JSON encoded payload. */
export function encryptPayload(key: Buffer, payload: Payload): EncryptedPayload {
  const plaintext = canonicalJSON(payload);
  const nonce = require('node:crypto').randomBytes(12) as Buffer;
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'AES-256-GCM',
    nonce: nonce.toString('base64'),
    ciphertext: Buffer.concat([enc, tag]).toString('base64'),
  };
}

export function decryptPayload(key: Buffer, enc: EncryptedPayload): Payload {
  if (enc.alg !== 'AES-256-GCM') {
    throw new Error(`unsupported alg ${enc.alg}`);
  }
  const nonce = Buffer.from(enc.nonce, 'base64');
  const ctWithTag = Buffer.from(enc.ciphertext, 'base64');
  if (ctWithTag.length < 16) {
    throw new Error('ciphertext too short');
  }
  const ct = ctWithTag.subarray(0, ctWithTag.length - 16);
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  const parsed = JSON.parse(pt.toString('utf8')) as Payload;
  return parsed;
}

export function verifyLicenseSignature(pub: KeyObject, lic: License): void {
  const sig = Buffer.from(lic.signature, 'base64');
  const clone: License = { ...lic, signature: '' };
  const msg = canonicalJSON(clone);
  const ok = edVerify(null, msg, pub, sig);
  if (!ok) throw new Error('ed25519 signature verification failed');
}

export function signLicense(priv: KeyObject, lic: License): void {
  lic.signature = '';
  const msg = canonicalJSON(lic);
  const sig = edSign(null, msg, priv);
  lic.signature = sig.toString('base64');
}

export function computeWatermarkMac(key: Buffer, wm: Watermark): string {
  const clone: Watermark = { ...wm, mac: '' };
  const msg = canonicalJSON(clone);
  return createHmac('sha256', key).update(msg).digest('base64');
}

export function verifyWatermarkMac(key: Buffer, wm: Watermark): void {
  const want = Buffer.from(computeWatermarkMac(key, wm), 'base64');
  const got = Buffer.from(wm.mac, 'base64');
  if (want.length !== got.length) {
    throw new Error('watermark MAC length mismatch');
  }
  // timing-safe compare
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want[i]! ^ got[i]!;
  if (diff !== 0) throw new Error('watermark MAC mismatch');
}
