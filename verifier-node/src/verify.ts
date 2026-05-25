// Public verification entrypoint. Mirrors internal/license/verify.go.
//
// Verify() is the only function Next.js should call. It is fully
// synchronous: there is no I/O fan-out, no network, no spawn other
// than nvidia-smi (which is part of fingerprinting). Verification of a
// healthy license on commodity hardware takes ~3 ms.

import { readFileSync } from 'node:fs';

import {
  License,
  VerifyResult,
  VerifyReason,
  FORMAT_VERSION,
  HKDF_INFO_PAYLOAD,
  HKDF_INFO_WATERMARK,
  MAX_TIME_REWINDS,
} from './types';
import {
  decryptPayload,
  deriveKey,
  fingerprintBytes,
  loadEd25519Public,
  verifyLicenseSignature,
} from './crypto';
import {
  FingerprintConfig,
  collectHardwareInfo,
  fingerprintConfigFromEnv,
} from './fingerprint';
import {
  advanceWatermark,
  loadWatermark,
  saveWatermark,
  validateWatermark,
  watermarkBelongsTo,
} from './watermark';

export interface VerifyOptions {
  licensePath: string;
  publicKeyPath: string;
  watermarkPath: string;
  fingerprint?: Partial<FingerprintConfig>;
  /** Override the wall clock; production callers leave undefined. */
  now?: Date;
  /** Optional diagnostic sink; the public VerifyResult deliberately omits details. */
  logger?: (event: VerifyEvent) => void;
}

export interface VerifyEvent {
  reason: VerifyReason;
  error?: Error;
  licenseId?: string;
  fingerprint?: string;
  now: Date;
  effective?: Date;
}

export function verifyLicense(opts: VerifyOptions): VerifyResult {
  const now = opts.now ?? new Date();
  const logger = opts.logger ?? (() => {});
  // Bare-metal host paths by default; switch to container bind-mount
  // paths only when HW_CONTAINER=1 (mirrors the Go CLI). Caller-provided
  // `fingerprint` overrides win regardless.
  const cfg: FingerprintConfig = { ...fingerprintConfigFromEnv(), ...(opts.fingerprint ?? {}) };

  const emit = (reason: VerifyReason, error?: Error, licenseId?: string, fingerprint?: string, effective?: Date): VerifyResult => {
    logger({ reason, error, licenseId, fingerprint, now, effective });
    return {
      valid: reason === 'ok',
      reason,
      licenseId: reason === 'ok' ? licenseId : undefined,
    };
  };

  // 1. Read + structurally validate the license.
  let lic: License;
  try {
    const raw = readFileSync(opts.licensePath, 'utf8');
    lic = JSON.parse(raw) as License;
  } catch (e) {
    return emit('malformed', e as Error);
  }
  if (lic.version !== FORMAT_VERSION) {
    return emit('unsupported_version', new Error(`got ${lic.version}, want ${FORMAT_VERSION}`), lic.id);
  }
  if (!lic.id || !lic.hardwareFingerprint || !lic.issuedAt) {
    return emit('malformed', new Error('missing required field'), lic.id);
  }
  // Permanent licenses carry the Go zero time ("0001-01-01T00:00:00Z");
  // only require a real notAfter for time-bound ones.
  if (lic.expires && !lic.notAfter) {
    return emit('malformed', new Error('expiring license missing notAfter'), lic.id);
  }

  // 2. Signature check.
  let pub;
  try {
    pub = loadEd25519Public(opts.publicKeyPath);
  } catch (e) {
    return emit('malformed', e as Error, lic.id);
  }
  try {
    verifyLicenseSignature(pub, lic);
  } catch (e) {
    return emit('signature_invalid', e as Error, lic.id);
  }

  // 3. Hardware fingerprint.
  let info;
  try {
    info = collectHardwareInfo(cfg);
  } catch (e) {
    return emit('hardware_unavailable', e as Error, lic.id);
  }
  if (info.fingerprint !== lic.hardwareFingerprint) {
    return emit('fingerprint_mismatch',
      new Error(`device fp ${info.fingerprint} != license fp ${lic.hardwareFingerprint}`),
      lic.id, info.fingerprint);
  }

  // 4. Derive keys.
  const fpBuf = fingerprintBytes(lic.hardwareFingerprint);
  const aesKey = deriveKey(fpBuf, lic.id, HKDF_INFO_PAYLOAD);
  const hmacKey = deriveKey(fpBuf, lic.id, HKDF_INFO_WATERMARK);

  // 5. Decrypt + payload cross-binding.
  let payload;
  try {
    payload = decryptPayload(aesKey, lic.encryptedPayload);
  } catch (e) {
    return emit('malformed', e as Error, lic.id, info.fingerprint);
  }
  if (payload.id !== lic.id) {
    return emit('payload_mismatch',
      new Error(`payload.id=${payload.id} != license.id=${lic.id}`),
      lic.id, info.fingerprint);
  }
  if (payload.expires !== lic.expires) {
    return emit('payload_mismatch',
      new Error(`payload.expires=${payload.expires} != license.expires=${lic.expires}`),
      lic.id, info.fingerprint);
  }
  if (payload.notAfter !== lic.notAfter) {
    return emit('payload_mismatch',
      new Error('payload.notAfter != license.notAfter'),
      lic.id, info.fingerprint);
  }

  // 6. Watermark.
  let wm;
  try {
    wm = loadWatermark(opts.watermarkPath, hmacKey);
  } catch (e) {
    return emit('watermark_tampered', e as Error, lic.id, info.fingerprint);
  }
  if (wm) {
    if (!watermarkBelongsTo(wm, lic)) {
      return emit('watermark_tampered',
        new Error(`watermark belongs to ${wm.licenseId}, not ${lic.id}`),
        lic.id, info.fingerprint);
    }
    try {
      validateWatermark(wm);
    } catch (e) {
      return emit('watermark_tampered', e as Error, lic.id, info.fingerprint);
    }
  }

  const adv = advanceWatermark(wm, lic, now);

  if (adv.next.timeRewindCount > MAX_TIME_REWINDS) {
    safeSave(opts.watermarkPath, hmacKey, adv.next);
    return emit('time_rewind',
      new Error(`time_rewind_count=${adv.next.timeRewindCount} > ${MAX_TIME_REWINDS}`),
      lic.id, info.fingerprint, adv.effective);
  }

  // 7. Time gates against the effective clock. NotBefore is enforced
  //    even for permanent licenses; the expired check only runs when
  //    lic.expires is true.
  const notBefore = new Date(lic.notBefore);
  if (adv.effective.getTime() < notBefore.getTime()) {
    safeSave(opts.watermarkPath, hmacKey, adv.next);
    return emit('not_yet_valid', undefined, lic.id, info.fingerprint, adv.effective);
  }
  const notAfter = lic.expires ? new Date(lic.notAfter) : null;
  if (notAfter && adv.effective.getTime() > notAfter.getTime()) {
    safeSave(opts.watermarkPath, hmacKey, adv.next);
    return emit('expired', undefined, lic.id, info.fingerprint, adv.effective);
  }

  // 8. Offline-duration cap, against real wall clock. Skipped for
  //    permanent licenses (the issuer forces maxOfflineDays=0 in that
  //    mode, but we guard explicitly in case a hand-crafted payload
  //    slips through).
  if (lic.expires && payload.maxOfflineDays > 0 && wm) {
    const gapMs = now.getTime() - new Date(wm.lastSeenAt).getTime();
    const gapDays = gapMs / 86_400_000;
    if (gapDays > payload.maxOfflineDays) {
      safeSave(opts.watermarkPath, hmacKey, adv.next);
      return emit('offline_too_long',
        new Error(`gap=${gapDays.toFixed(2)}d > ${payload.maxOfflineDays}d`),
        lic.id, info.fingerprint, adv.effective);
    }
  }

  // 9. Persist + return.
  try {
    saveWatermark(opts.watermarkPath, hmacKey, adv.next);
  } catch (e) {
    return emit('watermark_tampered', e as Error, lic.id, info.fingerprint, adv.effective);
  }

  logger({ reason: 'ok', licenseId: lic.id, fingerprint: info.fingerprint, now, effective: adv.effective });
  const result: VerifyResult = {
    valid: true,
    reason: 'ok',
    licenseId: lic.id,
    features: payload.features,
  };
  if (notAfter) {
    result.notAfter = lic.notAfter;
    result.daysLeft = Math.floor((notAfter.getTime() - adv.effective.getTime()) / 86_400_000);
  }
  return result;
}

function safeSave(filePath: string, key: Buffer, wm: import('./types').Watermark): void {
  try {
    saveWatermark(filePath, key, wm);
  } catch {
    // swallow — we already failed verification, this is best-effort persistence
  }
}
