# Next.js integration example

This folder shows how to plug `@yourorg/license-verifier` into a real
Next.js app. There are two supported deployment shapes:

| Shape | Defaults read from | Recommended for |
|-------|-------------------|-----------------|
| **Bare metal** (GB10 + PM2 + `npm start`) | `/sys/...`, `/proc/cmdline` | offline edge boxes you own physically |
| **Docker** (image + `docker compose up`) | `/host/sys/...`, `/host/cmdline` | shared infra / CI parity |

The verifier picks the right defaults automatically based on `HW_CONTAINER`:

- `HW_CONTAINER=1` → container bind-mount paths
- unset or `HW_CONTAINER=0` → bare-metal host paths

You only ever need to set per-device knobs (`HW_NIC`, `HW_DISK`,
`HW_REQUIRE_GPU`). All filesystem path defaults are correct out of
the box for both shapes.

---

## 1. Add the verifier package

```bash
# Option A: from a local checkout of this repo
cd verifier-node && npm run build && npm pack
cd ../examples/nextjs && npm install ../verifier-node/yourorg-license-verifier-1.0.0.tgz

# Option B: publish to your internal registry, then
npm install @yourorg/license-verifier
```

## 2. Drop in `instrumentation.ts`

Copy [`instrumentation.ts`](./instrumentation.ts) to the **root** of
your Next.js project (same level as `next.config.js` / `package.json`).
On Next.js 13.x also enable the hook in `next.config.js`
([example](./next.config.example.js)). Next.js 14+ has it on by default.

That single file is the entire integration surface. It calls
`verifyLicense()` once at startup, exits with code `78` on failure, and
re-checks every hour by default (`LICENSE_RECHECK_MS`).

## 3. Issue + place the license

On your **internal** signing host (not the device):

```bash
make issuer
./build/issuer sign \
  -hardware ./hardware.json \
  -priv ./private.pem \
  -licensee "ACME Corp" \
  -not-after 2027-05-21 \
  -features pro,ai-camera \
  -max-offline-days 90 \
  -out license.json
```

Then ship `license.json` + `public.pem` to the device. Both shapes
expect them in the directory referenced by `LICENSE_PATH` /
`LICENSE_PUBLIC_KEY` (default `/license/`, but on bare metal you
typically point them at e.g. `/opt/your-app/license/`).

The `.watermark` file is created automatically on first successful
verification and updated atomically on every subsequent one.

---

## 4a. Bare-metal deployment (PM2 + `npm start` on GB10)

Reference assets in this folder:

| File | Purpose |
|------|---------|
| `ecosystem.config.js` | PM2 process definition with all `HW_*` / `LICENSE_*` env vars |
| `license-app.service` | systemd unit that owns the PM2 daemon |

Step-by-step:

```bash
# 1. ship the built Next.js project to /opt/your-app/ on the GB10
sudo mkdir -p /opt/your-app
sudo rsync -a ./   /opt/your-app/      # (or: scp / git clone / etc.)

# 2. install dependencies + build on the device
cd /opt/your-app
sudo npm ci
sudo npm run build

# 3. drop the license + public key in place
sudo mkdir -p /opt/your-app/license
sudo cp /tmp/license.json /opt/your-app/license/
sudo cp /tmp/public.pem    /opt/your-app/license/

# 4. install PM2 globally
sudo npm install -g pm2

# 5. customise ecosystem.config.js  (HW_NIC / HW_DISK!)
sudo $EDITOR /opt/your-app/ecosystem.config.js

# 6. install systemd unit + enable
sudo cp examples/nextjs/license-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now license-app
sudo systemctl status  license-app
```

Verify it works:

```bash
journalctl -u license-app -f
# Expect a line like:
# {"kind":"license","reason":"ok","licenseId":"lic_...","fingerprint":"...","now":"...","effective":"..."}
# [license] OK id=lic_... daysLeft=362 features=pro,ai-camera
```

If it fails with `fingerprint_mismatch`, see the troubleshooting table
below.

### Why we run as root

The fingerprint includes `product_uuid`, `product_serial` and
`board_serial` from `/sys/class/dmi/id/`, which are typically mode
`0400 root:root` on Linux. The signed license was generated with
`sudo ./build/issuer sign -local`, so the runtime verifier must also
read those nodes — which means running as root.

If a non-root user reads them they silently come back empty, the
fingerprint becomes shorter, and verification fails with
`fingerprint_mismatch`.

### Running unprivileged (advanced, not recommended)

You can run as a normal user **only** if you also signed the license
without root, so neither side hashes the DMI nodes. Then:

```bash
# At signing time, on the device, as the SAME unprivileged user:
./build/issuer-device sign -local \
  -priv ./private.pem -licensee "ACME Corp" \
  -not-after 2027-05-21 -features pro,ai-camera \
  -nic enP7s7 -disk-name nvme0n1 -require-gpu \
  -out ./license/license.json
```

This drops `dmi_*` from `sources`, so the fingerprint becomes weaker
(it relies entirely on NVMe serial + GPU UUID + MAC + root UUID).
Acceptable on GB10 because those four sources alone are uniquely
tied to the box and uniformly hard to spoof. If your threat model
needs DMI you must run as root.

You can then change `User=root` to your service user in
`license-app.service` and use Linux capabilities or accept the
unprivileged setup.

---

## 4b. Docker deployment

The repo's `docker-compose.yml` already wires this up correctly. It
sets `HW_CONTAINER=1` and bind-mounts the right host paths:

| container path  | source                     | mode |
|-----------------|----------------------------|------|
| `/license/`     | `./license/` on host       | rw   |
| `/host/sys`     | `/sys`                     | ro   |
| `/host/cmdline` | `/proc/cmdline`            | ro   |
| `/host/nvidia-driver` | `/proc/driver/nvidia` | ro   |

Then:

```bash
docker compose up -d app
docker compose logs -f app
```

---

## Environment reference

The Next.js process honours these env vars (the same ones the Go CLI
uses, so issuer / verifier / Next.js stay in lock-step):

| Variable | Default (host) | Default (container) | Purpose |
|----------|----------------|---------------------|---------|
| `LICENSE_PATH` | `/license/license.json` | same | signed license |
| `LICENSE_PUBLIC_KEY` | `/license/public.pem` | same | Ed25519 public key |
| `LICENSE_WATERMARK` | `/license/.watermark` | same | monotonic watermark |
| `LICENSE_RECHECK_MS` | `3600000` | same | runtime re-check interval |
| `HW_CONTAINER` | unset | `1` | switches the path defaults |
| `HW_NIC` | `eth0` | `eth0` | **must** match real device NIC (e.g. `enP7s7` on GB10) |
| `HW_DISK` | *(auto-pick first NVMe)* | same | pin to e.g. `nvme0n1` |
| `HW_NVIDIA_SMI` | `nvidia-smi` | `nvidia-smi` | empty string disables GPU UUID |
| `HW_REQUIRE_GPU` | `0` | `0` | fail fast if GPU UUID missing |
| `HW_DMI` | *(only honoured when `HW_CONTAINER=1`)* | `/host/sys/class/dmi/id` | bind-mount override |
| `HW_NET` | *(idem)* | `/host/sys/class/net` | bind-mount override |
| `HW_BLOCK` | *(idem)* | `/host/sys/class/block` | bind-mount override |
| `HW_CMDLINE` | *(idem)* | `/host/cmdline` | bind-mount override |
| `HW_DT` | *(idem)* | `/proc/device-tree` | bind-mount override |
| `HW_FW_TREE` | *(idem)* | `/host/sys/firmware/devicetree/base` | bind-mount override |
| `HW_NVIDIA_PROC` | `/proc/driver/nvidia` | `/host/nvidia-driver` | nvidia driver proc dir |

> Path overrides (`HW_DMI`, `HW_NET`, …) are intentionally ignored on
> bare metal. They exist so a container can re-point at host bind
> mounts; applying them on bare metal silently breaks fingerprint
> parity with `issuer sign -local`.

---

## Troubleshooting

| Symptom (`reason` in log) | Likely cause | Fix |
|---------------------------|--------------|-----|
| `fingerprint_mismatch` | DMI nodes unreadable (running as non-root), wrong `HW_NIC`, swapped disk/GPU/NIC | run as root, or re-issue without DMI; double-check `ip -o link show` and `ls /sys/class/block` |
| `hardware_unavailable` | `HW_REQUIRE_GPU=1` but `nvidia-smi` not on PATH or no GPU visible | check `nvidia-smi` works for the same user as the service |
| `signature_invalid` | `public.pem` doesn't match the `private.pem` used to sign | redeploy correct public key |
| `expired` | `notAfter` in the past | re-issue |
| `offline_too_long` | device hasn't booted within `maxOfflineDays` | re-issue with longer window or just boot+verify on a schedule |
| `watermark_tampered` | `/opt/your-app/license/.watermark` modified out-of-band, or `LICENSE_WATERMARK` points at the wrong path | delete the watermark file; the verifier will re-create it on next startup |

A handy one-liner to compare what the device sees vs. what the license
expects:

```bash
sudo ./build/verifier -v \
  -pub /opt/your-app/license/public.pem \
  -license /opt/your-app/license/license.json \
  -nic enP7s7 -disk-name nvme0n1 -require-gpu
```

That's the same code path the Next.js process uses — if it says
`license: VALID` from the CLI but the Next.js app reports
`fingerprint_mismatch`, the difference is almost always `HW_NIC` /
`HW_DISK` env vars or non-root execution.
