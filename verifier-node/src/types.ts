// Shared shapes between the Go and Node verifiers. Any field name or
// semantic change here MUST be mirrored in internal/license/types.go.

export const FORMAT_VERSION = 4;
// HKDF info strings keep their v3 names on purpose — the derivation
// itself did not change, only the surrounding license schema did. Both
// Go and Node MUST use the exact same constants.
export const HKDF_INFO_PAYLOAD = 'license-v3:payload-aes-gcm';
export const HKDF_INFO_WATERMARK = 'license-v3:watermark-hmac';

export const TIME_REWIND_TOLERANCE_MS = 5 * 60 * 1000;
export const MAX_TIME_REWINDS = 3;

export interface EncryptedPayload {
  alg: 'AES-256-GCM';
  /** Base64-encoded 12-byte GCM nonce. */
  nonce: string;
  /** Base64-encoded ciphertext including the 16-byte GCM tag at the end. */
  ciphertext: string;
}

export interface License {
  version: number;
  id: string;
  /** RFC 3339 UTC timestamps as strings on the wire. */
  issuedAt: string;
  notBefore: string;
  /** "0001-01-01T00:00:00Z" (Go zero time) when expires=false. */
  notAfter: string;
  /** false = permanent license; expired / offline_too_long checks skipped. */
  expires: boolean;
  licensee: string;
  hardwareFingerprint: string;
  encryptedPayload: EncryptedPayload;
  /** Base64-encoded Ed25519 signature over canonical(license without signature). */
  signature: string;
}

export interface Payload {
  id: string;
  /** Must equal License.expires (cross-bound to defeat header swaps). */
  expires: boolean;
  /** Must equal License.notAfter (zero time when expires=false). */
  notAfter: string;
  features: string[];
  /** Always 0 for permanent licenses; the issuer enforces this. */
  maxOfflineDays: number;
  note?: string;
}

export interface HardwareInfo {
  schemaVersion: number;
  collectedAt: string;
  platform: string;
  nic: string;
  sources: Record<string, string>;
  fingerprint: string;
}

export interface Watermark {
  licenseId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  verifyCount: number;
  timeRewindCount: number;
  /** Base64-encoded HMAC-SHA256 over canonical(watermark without mac). */
  mac: string;
}

export type VerifyReason =
  | 'ok'
  | 'malformed'
  | 'unsupported_version'
  | 'signature_invalid'
  | 'fingerprint_mismatch'
  | 'payload_mismatch'
  | 'watermark_tampered'
  | 'time_rewind'
  | 'not_yet_valid'
  | 'expired'
  | 'offline_too_long'
  | 'hardware_unavailable';

export interface VerifyResult {
  valid: boolean;
  reason: VerifyReason;
  licenseId?: string;
  notAfter?: string;
  daysLeft?: number;
  features?: string[];
}
