// Drop this file at the project root of your Next.js app (alongside
// `next.config.js`). Next.js 13.4+ calls `register()` exactly once
// during process startup, before any HTTP handler runs.
//
// If `verifyLicense` returns invalid we `process.exit(78)` immediately
// so the app never serves a request without a valid license. Combined
// with the verifier's in-process semantics, there is no network hop
// an attacker could intercept or replace.
//
// Path defaults (mirrors @yourorg/license-verifier):
//   - `HW_CONTAINER=1`  -> /host/sys/..., /host/cmdline (Docker)
//   - otherwise         -> /sys/..., /proc/cmdline       (bare metal,
//                                                         e.g. PM2 +
//                                                         npm start
//                                                         on GB10)

const LICENSE_PATH = process.env.LICENSE_PATH ?? '/license/license.json';
const LICENSE_PUBLIC_KEY = process.env.LICENSE_PUBLIC_KEY ?? '/license/public.pem';
const LICENSE_WATERMARK = process.env.LICENSE_WATERMARK ?? '/license/.watermark';

function fingerprintOverrides() {
  // Only overlay knobs the operator is *expected* to set per device.
  // Path defaults come from fingerprintConfigFromEnv() inside the
  // verifier, so we don't need to repeat /sys/... vs /host/sys/...
  // here.
  const overrides: Record<string, unknown> = {};
  if (process.env.HW_NIC) overrides.nicName = process.env.HW_NIC;
  if (process.env.HW_DISK) overrides.diskName = process.env.HW_DISK;
  if (process.env.HW_NVIDIA_SMI) overrides.nvidiaSmi = process.env.HW_NVIDIA_SMI;
  if (process.env.HW_REQUIRE_GPU !== undefined) {
    overrides.requireGpu = process.env.HW_REQUIRE_GPU === '1';
  }
  return overrides;
}

export async function register() {
  // Edge runtime has no fs/crypto: only run the check on the Node side.
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;

  const { verifyLicense } = await import('@yourorg/license-verifier');

  const runVerify = () =>
    verifyLicense({
      licensePath: LICENSE_PATH,
      publicKeyPath: LICENSE_PUBLIC_KEY,
      watermarkPath: LICENSE_WATERMARK,
      fingerprint: fingerprintOverrides(),
      logger: (ev) => {
        // structured single-line log for ops tooling
        console.error(JSON.stringify({
          kind: 'license',
          reason: ev.reason,
          licenseId: ev.licenseId,
          fingerprint: ev.fingerprint?.slice(0, 12),
          now: ev.now.toISOString(),
          effective: ev.effective?.toISOString(),
          err: ev.error?.message,
        }));
      },
    });

  const result = runVerify();
  if (!result.valid) {
    console.error(`[license] startup verification failed: ${result.reason}`);
    // Distinctive exit code so supervisord / systemd / pm2 can
    // distinguish license failures from generic crashes.
    process.exit(78); // EX_CONFIG-ish
  }

  console.error(
    `[license] OK id=${result.licenseId} daysLeft=${result.daysLeft} features=${(result.features ?? []).join(',')}`,
  );

  // Background re-check every hour. If the license expires while the
  // app is running (very long uptime, or operator shifted the clock
  // forward) we don't want to keep serving stale.
  const interval = Number(process.env.LICENSE_RECHECK_MS ?? 60 * 60 * 1000);
  if (interval > 0) {
    const timer = setInterval(() => {
      const r = runVerify();
      if (!r.valid) {
        console.error(`[license] runtime check failed: ${r.reason}`);
        process.exit(78);
      }
    }, interval);
    timer.unref();
  }
}
