// Watermark file I/O and the monotonic-clock advancement policy.
// Mirrors internal/license/watermark.go.

import { readFileSync, writeFileSync, renameSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import * as path from 'node:path';

import { Watermark, License, TIME_REWIND_TOLERANCE_MS } from './types';
import { computeWatermarkMac, verifyWatermarkMac } from './crypto';

export function loadWatermark(filePath: string, key: Buffer): Watermark | null {
  try {
    statSync(filePath);
  } catch {
    return null;
  }
  const raw = readFileSync(filePath, 'utf8');
  const wm = JSON.parse(raw) as Watermark;
  // Strict-mode would also reject unknown fields; in JS we just rely on
  // the MAC: any extra/missing field changes the canonical bytes and
  // breaks verification.
  verifyWatermarkMac(key, wm);
  return wm;
}

export function saveWatermark(filePath: string, key: Buffer, wm: Watermark): void {
  wm.mac = computeWatermarkMac(key, wm);
  const data = JSON.stringify(wm, null, 2) + '\n';
  const dir = path.dirname(filePath);
  const tmpDir = mkdtempSync(path.join(dir, '.wm-'));
  const tmpFile = path.join(tmpDir, 'watermark.tmp');
  try {
    writeFileSync(tmpFile, data, { mode: 0o600 });
    renameSync(tmpFile, filePath);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

export interface AdvanceResult {
  next: Watermark;
  effective: Date;
  rewind: boolean;
}

export function advanceWatermark(prev: Watermark | null, lic: License, now: Date): AdvanceResult {
  if (!prev) {
    const issued = new Date(lic.issuedAt);
    const fs = now.getTime() > issued.getTime() ? now : issued;
    const wm: Watermark = {
      licenseId: lic.id,
      firstSeenAt: fs.toISOString(),
      lastSeenAt: fs.toISOString(),
      verifyCount: 1,
      timeRewindCount: 0,
      mac: '',
    };
    return { next: wm, effective: fs, rewind: false };
  }

  const next: Watermark = { ...prev };
  next.verifyCount = prev.verifyCount + 1;

  const lastSeen = new Date(prev.lastSeenAt);
  let effective = lastSeen;
  let rewind = false;

  if (now.getTime() > lastSeen.getTime()) {
    next.lastSeenAt = now.toISOString();
    effective = now;
  } else if (lastSeen.getTime() - now.getTime() > TIME_REWIND_TOLERANCE_MS) {
    next.timeRewindCount = prev.timeRewindCount + 1;
    rewind = true;
  }
  return { next, effective, rewind };
}

export function watermarkBelongsTo(wm: Watermark, lic: License): boolean {
  return wm.licenseId === lic.id;
}

export function validateWatermark(wm: Watermark | null): asserts wm is Watermark {
  if (!wm) throw new Error('nil watermark');
  if (!wm.licenseId) throw new Error('watermark missing licenseId');
  if (!wm.firstSeenAt || !wm.lastSeenAt) throw new Error('watermark missing timestamps');
  if (new Date(wm.lastSeenAt).getTime() < new Date(wm.firstSeenAt).getTime()) {
    throw new Error('watermark lastSeenAt < firstSeenAt');
  }
}
