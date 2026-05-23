// Cross-language consistency test: Go issuer/CLI produces artifacts,
// Node verifier consumes them. Run with:
//   npm run build && node --test test/cross.test.js
//
// Uses a synthetic /host tree under tmp so we don't depend on real
// hardware paths.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync, rmSync, mkdirSync, existsSync } = require('node:fs');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');

const { verifyLicense, computeFingerprint } = require('../dist');

function sh(cmd, args, cwd) {
  return execFileSync(cmd, args, { encoding: 'utf8', cwd });
}

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER_BIN = path.join(REPO_ROOT, 'build', 'issuer');

if (!existsSync(ISSUER_BIN)) {
  sh('go', ['build', '-o', ISSUER_BIN, './cmd/issuer'], REPO_ROOT);
}

function setup(tmp) {
  const hostDir = path.join(tmp, 'host');
  const dmiDir = path.join(hostDir, 'dmi');
  const netDir = path.join(hostDir, 'net', 'eth0');
  const blockDir = path.join(hostDir, 'block');
  const diskDir = path.join(blockDir, 'nvme0n1');
  mkdirSync(dmiDir, { recursive: true });
  mkdirSync(netDir, { recursive: true });
  mkdirSync(path.join(diskDir, 'device'), { recursive: true });
  writeFileSync(path.join(dmiDir, 'product_uuid'), 'AAAA-BBBB-CCCC-DDDD\n');
  writeFileSync(path.join(dmiDir, 'board_serial'), 'BOARD-1234\n');
  writeFileSync(path.join(dmiDir, 'sys_vendor'), 'XFUSION\n');
  writeFileSync(path.join(dmiDir, 'product_name'), 'FusionXpark GB10\n');
  writeFileSync(path.join(netDir, 'address'), 'aa:bb:cc:dd:ee:ff\n');
  // Simulate the kernel's trailing-whitespace padding on /sys/block/*/device/serial
  writeFileSync(path.join(diskDir, 'device', 'serial'), 'TESTSERIAL12345   \n');
  writeFileSync(path.join(diskDir, 'wwid'), 'eui.00000000000000006479a7b4ea30bc37\n');
  writeFileSync(path.join(hostDir, 'cmdline'),
    'BOOT_IMAGE=/vmlinuz root=UUID=feedface-1234-5678-90ab-cdef00112233 ro\n');
  return {
    hostDir, dmiDir,
    fpCfg: {
      dmiDir,
      deviceTreeDir: path.join(hostDir, 'dt'),
      firmwareTreeDir: path.join(hostDir, 'fwtree'),
      netDir: path.join(hostDir, 'net'),
      nicName: 'eth0',
      cmdlinePath: path.join(hostDir, 'cmdline'),
      blockDir,
      diskName: '',
      nvidiaSmi: '',
      requireGpu: false,
    },
    sources: {
      product_uuid: 'AAAA-BBBB-CCCC-DDDD',
      board_serial: 'BOARD-1234',
      dmi_sys_vendor: 'XFUSION',
      dmi_product_name: 'FusionXpark GB10',
      host_mac: 'aa:bb:cc:dd:ee:ff',
      root_uuid: 'UUID:feedface-1234-5678-90ab-cdef00112233',
      disk_serial: 'TESTSERIAL12345',
      disk_wwid: 'eui.00000000000000006479a7b4ea30bc37',
    },
  };
}

function issueLicense(tmp, sources, opts = {}) {
  const fp = computeFingerprint(sources);
  const hwPath = path.join(tmp, 'hardware.json');
  writeFileSync(hwPath, JSON.stringify({
    schemaVersion: 1,
    collectedAt: new Date().toISOString(),
    platform: 'linux/amd64',
    nic: 'eth0',
    sources,
    fingerprint: fp,
  }, null, 2));

  const privPath = path.join(tmp, 'private.pem');
  const pubPath = path.join(tmp, 'public.pem');
  sh(ISSUER_BIN, ['keygen', '-priv', privPath, '-pub', pubPath]);

  const licPath = path.join(tmp, 'license.json');
  const args = [
    'sign',
    '-hardware', hwPath,
    '-priv', privPath,
    '-licensee', 'TEST',
    '-not-after', opts.notAfter || new Date(Date.now() + 86_400_000).toISOString(),
    '-features', opts.features || 'pro,ai',
    '-out', licPath,
  ];
  if (opts.maxOfflineDays) args.push('-max-offline-days', String(opts.maxOfflineDays));
  sh(ISSUER_BIN, args);
  return { licPath, pubPath, privPath };
}

test('happy path: issue then verify', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    const { licPath, pubPath } = issueLicense(tmp, env.sources);
    const watermarkPath = path.join(tmp, '.watermark');

    const r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, true, `got ${r.reason}`);
    assert.deepEqual(r.features, ['pro', 'ai']);
    assert.ok(r.licenseId.startsWith('lic_'));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('fingerprint mismatch is rejected', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    const { licPath, pubPath } = issueLicense(tmp, env.sources);
    const watermarkPath = path.join(tmp, '.watermark');

    // Change MAC after issuance → fingerprint moves
    writeFileSync(path.join(env.hostDir, 'net', 'eth0', 'address'), '11:22:33:44:55:66\n');

    const r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'fingerprint_mismatch');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('expired license is rejected', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    // Issue a license that expired one second ago.
    const past = new Date(Date.now() - 1000).toISOString();
    const { licPath, pubPath } = issueLicense(tmp, env.sources, { notAfter: past });
    const watermarkPath = path.join(tmp, '.watermark');

    const r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'expired');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('time rewind: too many backwards jumps trip the lock', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    const { licPath, pubPath } = issueLicense(tmp, env.sources);
    const watermarkPath = path.join(tmp, '.watermark');

    // Establish a healthy watermark with now=real
    let r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, true);

    // Now rewind several times.
    const past = new Date(Date.now() - 30 * 86_400_000);
    let lastReason = '';
    for (let i = 0; i < 5; i++) {
      r = verifyLicense({
        licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
        now: past,
        fingerprint: env.fpCfg,
      });
      lastReason = r.reason;
    }
    assert.equal(r.valid, false);
    assert.equal(lastReason, 'time_rewind');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('watermark tamper is detected', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    const { licPath, pubPath } = issueLicense(tmp, env.sources);
    const watermarkPath = path.join(tmp, '.watermark');

    let r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, true);

    // Corrupt the watermark.
    writeFileSync(watermarkPath, '{"licenseId":"forged","firstSeenAt":"2020-01-01T00:00:00Z","lastSeenAt":"2020-01-01T00:00:00Z","verifyCount":0,"timeRewindCount":0,"mac":"AAAA"}\n');

    r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'watermark_tampered');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('signature tamper is detected', () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    const env = setup(tmp);
    const { licPath, pubPath } = issueLicense(tmp, env.sources);
    const watermarkPath = path.join(tmp, '.watermark');

    // Flip one character in the license body (extend the licensee).
    const fs = require('node:fs');
    const lic = JSON.parse(fs.readFileSync(licPath, 'utf8'));
    lic.licensee = 'EVIL Corp';
    fs.writeFileSync(licPath, JSON.stringify(lic, null, 2));

    const r = verifyLicense({
      licensePath: licPath, publicKeyPath: pubPath, watermarkPath,
      fingerprint: env.fpCfg,
    });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'signature_invalid');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
