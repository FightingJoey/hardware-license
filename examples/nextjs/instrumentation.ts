// Drop this file at the project root of your Next.js app (alongside
// `next.config.js`). Next.js 13.4+ calls `register()` exactly once
// during process startup, before any HTTP handler runs.
//
// If `verifyLicense` returns invalid, we `process.exit(1)` immediately
// so the app never serves a request without a valid license. Combined
// with the verifier's in-process semantics, there is no network hop
// an attacker could intercept or replace.

export async function register() {
  // Edge runtime has no fs/crypto: only run the check on the Node side.
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;

  const { verifyLicense } = await import('@yourorg/license-verifier');

  const result = verifyLicense({
    licensePath: process.env.LICENSE_PATH ?? '/license/license.json',
    publicKeyPath: process.env.LICENSE_PUBLIC_KEY ?? '/license/public.pem',
    watermarkPath: process.env.LICENSE_WATERMARK ?? '/license/.watermark',
    fingerprint: {
      // Most paths (dmiDir/netDir/blockDir/cmdlinePath/...) come from
      // defaultLinuxConfig() which reads HW_* env vars; we only need
      // to surface the policy knobs here.
      nicName: process.env.HW_NIC ?? 'eth0',
      diskName: process.env.HW_DISK ?? '',
      nvidiaSmi: process.env.HW_NVIDIA_SMI ?? 'nvidia-smi',
      requireGpu: process.env.HW_REQUIRE_GPU === '1',
    },
    logger: (ev) => {
      const meta = {
        reason: ev.reason,
        licenseId: ev.licenseId,
        fingerprint: ev.fingerprint?.slice(0, 12),
        now: ev.now.toISOString(),
        effective: ev.effective?.toISOString(),
        err: ev.error?.message,
      };
      // structured single-line log for ops tooling
      console.error(JSON.stringify({ kind: 'license', ...meta }));
    },
  });

  if (!result.valid) {
    console.error(`[license] startup verification failed: ${result.reason}`);
    // Use a distinctive exit code so supervisord/systemd alerts can
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
      const r = verifyLicense({
        licensePath: process.env.LICENSE_PATH ?? '/license/license.json',
        publicKeyPath: process.env.LICENSE_PUBLIC_KEY ?? '/license/public.pem',
        watermarkPath: process.env.LICENSE_WATERMARK ?? '/license/.watermark',
        fingerprint: {
          nicName: process.env.HW_NIC ?? 'eth0',
          diskName: process.env.HW_DISK ?? '',
          nvidiaSmi: process.env.HW_NVIDIA_SMI ?? 'nvidia-smi',
          requireGpu: process.env.HW_REQUIRE_GPU === '1',
        },
      });
      if (!r.valid) {
        console.error(`[license] runtime check failed: ${r.reason}`);
        process.exit(78);
      }
    }, interval);
    timer.unref();
  }
}
