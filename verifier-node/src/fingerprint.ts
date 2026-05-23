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

export function defaultLinuxConfig(): FingerprintConfig {
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
