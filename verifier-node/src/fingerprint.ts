// Hardware fingerprint collector for the device side. Mirrors
// internal/license/fingerprint.go byte-for-byte.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import type { HardwareInfo } from './types';

export interface FingerprintConfig {
  /** /sys/class/dmi/id (or host bind-mount). */
  dmiDir: string;
  /** /proc/device-tree (preferred). */
  deviceTreeDir: string;
  /** /sys/firmware/devicetree/base (sysfs fallback). */
  firmwareTreeDir?: string;
  /** /sys/class/net root. */
  netDir: string;
  /** Host NIC name whose MAC participates in the fingerprint. */
  nicName: string;
  /** /proc/cmdline or host bind-mount. */
  cmdlinePath: string;
  /** /sys/class/block (block-device sysfs root). */
  blockDir?: string;
  /** Pinned block device (e.g. "nvme0n1"); empty = auto-pick first NVMe. */
  diskName?: string;
  /** nvidia-smi binary or empty to skip. */
  nvidiaSmi?: string;
  /** Host nvidia driver proc root (container: /host/nvidia-driver). */
  nvidiaProcDir?: string;
  /** Fail if GPU UUID is unavailable. */
  requireGpu?: boolean;
}

/**
 * Bare-metal / host-namespace defaults. Use this when the Next.js
 * process runs directly on the licensed device (e.g. systemd / PM2 +
 * `npm start` on GB10) and `/sys`, `/proc` are the kernel's real
 * filesystems rather than container bind-mounts.
 *
 * Mirrors {@code internal/license/fingerprint.go::DefaultHostConfig}
 * byte-for-byte.
 */
export function defaultHostConfig(): FingerprintConfig {
  return {
    dmiDir: '/sys/class/dmi/id',
    deviceTreeDir: '/proc/device-tree',
    firmwareTreeDir: '/sys/firmware/devicetree/base',
    netDir: '/sys/class/net',
    nicName: process.env.HW_NIC ?? 'eth0',
    cmdlinePath: '/proc/cmdline',
    blockDir: '/sys/class/block',
    diskName: process.env.HW_DISK ?? '',
    nvidiaSmi: process.env.HW_NVIDIA_SMI ?? 'nvidia-smi',
    nvidiaProcDir: process.env.HW_NVIDIA_PROC ?? '/proc/driver/nvidia',
    requireGpu: false,
  };
}

/**
 * Container defaults — the Next.js process runs inside Docker with
 * /sys bind-mounted at /host/sys, /proc/cmdline at /host/cmdline,
 * and /proc/driver/nvidia at /host/nvidia-driver. See the reference
 * docker-compose.yml at the repo root.
 */
export function defaultContainerConfig(): FingerprintConfig {
  return {
    dmiDir: '/host/sys/class/dmi/id',
    deviceTreeDir: '/proc/device-tree',
    firmwareTreeDir: '/host/sys/firmware/devicetree/base',
    netDir: '/host/sys/class/net',
    nicName: process.env.HW_NIC ?? 'eth0',
    cmdlinePath: '/host/cmdline',
    blockDir: '/host/sys/class/block',
    diskName: process.env.HW_DISK ?? '',
    nvidiaSmi: process.env.HW_NVIDIA_SMI ?? 'nvidia-smi',
    nvidiaProcDir: process.env.HW_NVIDIA_PROC ?? '/host/nvidia-driver',
    requireGpu: false,
  };
}

/**
 * Resolve the fingerprint layout the same way the Go CLI does:
 *
 *   - if `forceContainer === true` (or env `HW_CONTAINER=1`), use the
 *     container bind-mount paths (`/host/sys/...`, `/host/cmdline`)
 *   - otherwise use bare-metal host paths (`/sys/...`, `/proc/cmdline`)
 *
 * Callers may overlay extra config on top of the returned object.
 *
 * `HW_DMI`, `HW_NET`, `HW_BLOCK`, `HW_CMDLINE`, `HW_DT`, `HW_FW_TREE`
 * are honoured **only in container mode**, exactly like the Go side.
 * Applying these on bare metal silently breaks fingerprint parity
 * with `issuer sign -local`, so we refuse to do it.
 */
export function fingerprintConfigFromEnv(forceContainer?: boolean): FingerprintConfig {
  const useContainer = forceContainer ?? (process.env.HW_CONTAINER === '1');
  const cfg = useContainer ? defaultContainerConfig() : defaultHostConfig();
  if (useContainer) {
    if (process.env.HW_DMI) cfg.dmiDir = process.env.HW_DMI;
    if (process.env.HW_DT) cfg.deviceTreeDir = process.env.HW_DT;
    if (process.env.HW_FW_TREE) cfg.firmwareTreeDir = process.env.HW_FW_TREE;
    if (process.env.HW_NET) cfg.netDir = process.env.HW_NET;
    if (process.env.HW_CMDLINE) cfg.cmdlinePath = process.env.HW_CMDLINE;
    if (process.env.HW_BLOCK) cfg.blockDir = process.env.HW_BLOCK;
  }
  if (process.env.HW_REQUIRE_GPU !== undefined) {
    cfg.requireGpu = process.env.HW_REQUIRE_GPU === '1' || process.env.HW_REQUIRE_GPU === 'true';
  }
  return cfg;
}

/**
 * @deprecated Use {@link fingerprintConfigFromEnv} (env-aware) or one
 * of {@link defaultHostConfig} / {@link defaultContainerConfig}
 * (explicit). Kept for backward compatibility — historically this
 * returned **container** defaults; that behaviour is preserved.
 */
export function defaultLinuxConfig(): FingerprintConfig {
  return defaultContainerConfig();
}

export function collectSources(cfg: FingerprintConfig): Record<string, string> {
  const sources: Record<string, string> = {};

  // 1) DMI / SMBIOS.
  addIfNonEmpty(sources, 'product_uuid', readTrimmed(path.join(cfg.dmiDir, 'product_uuid')));
  addIfNonEmpty(sources, 'product_serial', readTrimmed(path.join(cfg.dmiDir, 'product_serial')));
  addIfNonEmpty(sources, 'board_serial', readTrimmed(path.join(cfg.dmiDir, 'board_serial')));
  addIfNonEmpty(sources, 'dmi_sys_vendor', readTrimmed(path.join(cfg.dmiDir, 'sys_vendor')));
  addIfNonEmpty(sources, 'dmi_product_name', readTrimmed(path.join(cfg.dmiDir, 'product_name')));

  // 2) Device tree, with sysfs fallback.
  addIfNonEmpty(
    sources,
    'dt_serial_number',
    firstNonEmpty(
      readTrimmedNullStripped(path.join(cfg.deviceTreeDir, 'serial-number')),
      cfg.firmwareTreeDir ? readTrimmedNullStripped(path.join(cfg.firmwareTreeDir, 'serial-number')) : ''
    )
  );
  addIfNonEmpty(
    sources,
    'dt_model',
    firstNonEmpty(
      readTrimmedNullStripped(path.join(cfg.deviceTreeDir, 'model')),
      cfg.firmwareTreeDir ? readTrimmedNullStripped(path.join(cfg.firmwareTreeDir, 'model')) : ''
    )
  );

  // 3) Pinned NIC.
  if (cfg.nicName) {
    const mac = readTrimmed(path.join(cfg.netDir, cfg.nicName, 'address'));
    if (mac && mac !== '00:00:00:00:00:00') {
      sources['host_mac'] = mac.toLowerCase();
    }
  }

  // 4) Root UUID from kernel cmdline.
  const rootUuid = extractRootUuid(readTrimmed(cfg.cmdlinePath));
  if (rootUuid) sources['root_uuid'] = rootUuid;

  // 5) Block-device identity (the strongest source on OEM ARM boards).
  if (cfg.blockDir) {
    const disk = chooseBlockDevice(cfg);
    if (disk) {
      addIfNonEmpty(sources, 'disk_serial', readTrimmed(path.join(cfg.blockDir, disk, 'device', 'serial')));
      addIfNonEmpty(sources, 'disk_wwid', readTrimmed(path.join(cfg.blockDir, disk, 'wwid')));
    }
  }

  // 6) GPU UUID.
  const gpu = queryGpuUuid(cfg);
  if (gpu) {
    sources['gpu_uuid'] = gpu;
  } else if (cfg.requireGpu) {
    throw new Error('gpu uuid required but unavailable');
  }

  if (Object.keys(sources).length === 0) {
    throw new Error('no hardware identity sources available');
  }
  return sources;
}

export function computeFingerprint(sources: Record<string, string>): string {
  const keys = Object.keys(sources).sort();
  if (keys.length === 0) throw new Error('empty sources');
  const h = createHash('sha256');
  keys.forEach((k, i) => {
    if (i > 0) h.update(Buffer.from([0x1f]));
    h.update(k, 'utf8');
    h.update(Buffer.from([0x3d]));
    h.update(sources[k]!, 'utf8');
  });
  return h.digest('hex');
}

export function collectHardwareInfo(cfg: FingerprintConfig): HardwareInfo {
  const sources = collectSources(cfg);
  const fp = computeFingerprint(sources);
  return {
    schemaVersion: 1,
    collectedAt: new Date().toISOString(),
    platform: `${os.platform()}/${os.arch()}`,
    nic: cfg.nicName,
    sources,
    fingerprint: fp,
  };
}

// --- internals --------------------------------------------------------------

function addIfNonEmpty(map: Record<string, string>, key: string, val: string): void {
  const v = val.trim();
  if (!v || v === 'N/A' || v === 'Not Specified' || v === 'Default string') return;
  map[key] = v;
}

function readTrimmed(filePath: string): string {
  if (!filePath) return '';
  try {
    statSync(filePath);
  } catch {
    return '';
  }
  try {
    return readFileSync(filePath, 'utf8').trim();
  } catch {
    return '';
  }
}

function readTrimmedNullStripped(filePath: string): string {
  return readTrimmed(filePath).replace(/\x00+$/g, '');
}

function extractRootUuid(cmdline: string): string {
  for (const tok of cmdline.split(/\s+/)) {
    if (!tok.startsWith('root=')) continue;
    const v = tok.slice(5);
    if (v.startsWith('UUID=')) return 'UUID:' + v.slice(5);
    if (v.startsWith('PARTUUID=')) return 'PARTUUID:' + v.slice(9);
  }
  return '';
}

const NVME_NAMESPACE_RE = /^nvme\d+n\d+$/;
const MMC_DEVICE_RE = /^mmcblk\d+$/;

function chooseBlockDevice(cfg: FingerprintConfig): string {
  if (!cfg.blockDir) return '';
  if (cfg.diskName) {
    try {
      statSync(path.join(cfg.blockDir, cfg.diskName, 'device', 'serial'));
      return cfg.diskName;
    } catch {
      return '';
    }
  }
  let entries: string[];
  try {
    entries = readdirSync(cfg.blockDir);
  } catch {
    return '';
  }
  const nvmes: string[] = [];
  const mmcs: string[] = [];
  for (const name of entries) {
    if (NVME_NAMESPACE_RE.test(name)) nvmes.push(name);
    else if (MMC_DEVICE_RE.test(name)) mmcs.push(name);
  }
  nvmes.sort();
  mmcs.sort();
  for (const candidate of [...nvmes, ...mmcs]) {
    try {
      statSync(path.join(cfg.blockDir, candidate, 'device', 'serial'));
      return candidate;
    } catch {
      // try next
    }
  }
  return '';
}

function firstNonEmpty(...values: string[]): string {
  for (const v of values) {
    if (v && v.trim() !== '') return v;
  }
  return '';
}

function queryGpuUuid(cfg: FingerprintConfig): string {
  if (cfg.nvidiaSmi) {
    try {
      const out = execFileSync(cfg.nvidiaSmi, ['--query-gpu=uuid', '--format=csv,noheader'], {
        encoding: 'utf8',
        timeout: 3000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const first = out.trim().split('\n')[0]?.trim();
      if (first) return first;
    } catch {
      // fall through
    }
  }
  try {
    const dir = path.join(cfg.nvidiaProcDir ?? '/proc/driver/nvidia', 'gpus');
    for (const entry of readdirSync(dir)) {
      const info = readTrimmed(path.join(dir, entry, 'information'));
      for (const line of info.split('\n')) {
        if (line.startsWith('GPU UUID:')) {
          return line.slice('GPU UUID:'.length).trim();
        }
      }
    }
  } catch {
    // ignore
  }
  return '';
}
