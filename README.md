# hardware-license

面向**断网设备**的硬件绑定许可证系统（针对 NVIDIA GB10 等离线部署场景设计）。

| 组件 | 部署位置 | 携带密钥 | 用途 |
|------|----------|----------|------|
| `issuer`（Go CLI） | 内网主机 **或** 被授权设备 | `private.pem`（签发时） | 生成 `license.json`；支持读取 `hardware.json` 或在设备上 `-local` 采集后签发 |
| `licensedb`（Go CLI） | **仅内网签发主机** | 无 | 将已签发的 License 元数据写入远端 MySQL |
| `issue-and-store.sh` | **仅内网签发主机** | 无 | 封装 `issuer sign` + `licensedb store` 的一键签发入库脚本 |
| `hwinfo`（Go CLI） | 被授权设备 | 无 | 读取 `/sys`/`/proc`，输出 `hardware.json` 供签发 |
| `verifier`（Go CLI） | 被授权设备 | `public.pem` | 运维/调试用 CLI，与 Node 库走同一套验证逻辑 |
| `@yourorg/license-verifier`（Node 库） | 被授权设备，**嵌入 Next.js 进程** | `public.pem` | 应用启动时及每小时执行的**权威**进程内校验 |

**格式：v3** — Ed25519 签名、AES-256-GCM 加密载荷、HKDF-SHA256 密钥派生、多源宿主机指纹、HMAC 保护的单调时钟水位文件。Canonical JSON（RFC 8785）保证 Go 与 Node 字节级兼容。

---

## 威胁模型

目标设备在部署后**完全断网**。攻击者可能拥有物理访问权限和 root 权限，但无法联网，因此验证器不能回连服务器，所有防护必须在本地完成。

本方案不承诺「无法破解」，但承诺：要绕过授权，需要**逆向工程验证器二进制**，而不是读文档或执行几条 `docker` 命令。旧方案中的典型问题（私钥随设备镜像分发、生成接口暴露在设备上、容器内不可靠的硬件指纹、通过 HTTP 做鉴权）均已消除。

---

## 构建

```bash
make all          # 构建 Go CLI + Node 验证库
make test         # 6 项跨语言测试（Go 签发 → Node 验证）
```

产物及目标平台：

| 文件 | 目标平台 | 说明 |
|------|----------|------|
| `build/issuer` | 宿主机原生 | 内网签发主机使用（macOS / Linux / Windows 均可） |
| `build/issuer-device` | **linux/arm64**（默认） | 被授权设备上本地签发（`issuer sign -local`） |
| `build/licensedb` | 宿主机原生 | 签发后将 License 记录写入远端 MySQL |
| `build/hwinfo` | **linux/arm64**（默认） | 部署到 GB10 设备 |
| `build/verifier` | **linux/arm64**（默认） | 部署到 GB10 设备 |
| `verifier-node/dist/` | Node.js（跨平台） | Next.js 引用的编译后 CommonJS |

`hwinfo` 与 `verifier` 始终交叉编译为 Linux ELF，即使在 macOS 上 `make` 也能直接产出可 `scp` 到设备的二进制。如需 amd64 或其他架构，按需覆盖：

```bash
make hwinfo verifier TARGET_ARCH=amd64     # x86_64 设备
make hwinfo verifier TARGET_OS=linux TARGET_ARCH=arm   # 32 位 ARM
```

验证构建结果：

```bash
file build/hwinfo build/verifier
# build/hwinfo:   ELF 64-bit LSB executable, ARM aarch64 ...
# build/verifier: ELF 64-bit LSB executable, ARM aarch64 ...
```

---

## 端到端流程

### 1. 生成签名密钥对（一次性，在内网主机执行）

```bash
./build/issuer keygen -priv private.pem -pub public.pem
```

`private.pem` 只保留在内网签发主机。仅将 `public.pem` 分发到设备镜像和 Next.js 项目。

### 2. 采集设备硬件指纹

> 先确认 GB10 设备上的真实网卡名和 NVMe 盘符（不能直接套 `eth0` / `sda`）：
>
> ```bash
> ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2}'   # 例如得到 enP7s7
> ls /sys/class/block | grep -E '^nvme[0-9]+n[0-9]+$'      # 例如得到 nvme0n1
> ```

```bash
sudo ./build/hwinfo \
  -nic enP7s7 \
  -disk-name nvme0n1 \
  -require-gpu \
  -out hardware.json
```

> GB10 等 Linux 设备上，`/sys/class/dmi/id/product_uuid` 等 DMI 节点通常仅 **root 可读**。`hwinfo`、`issuer sign -local`、`verifier` 在宿主机上运行时请使用 `sudo`，否则指纹会缺少 DMI 字段，与 sudo 签发的 license 不一致。

> 宿主机上跑 `verifier` 时，请勿 export `HW_DMI=/host/sys/...` 等容器路径环境变量（那是 `docker-compose.yml` 给容器用的）。新版 CLI 在 bare-metal 模式下会忽略它们；也可显式加 `-host`。

容器内等价命令见 `docs/hardware-fingerprint.md`。

输出 JSON 包含所有可用的身份源（DMI 厂商/型号、device-tree、网卡 MAC、root UUID、**NVMe 工厂 serial / WWID**、GPU UUID）及其 SHA-256 指纹。该文件不含任何密钥，可安全通过 U 盘或邮件传输。详见 [docs/hardware-fingerprint.md](docs/hardware-fingerprint.md)。

### 3. 内网签发 License

在内网主机上（读取设备传来的 `hardware.json`）：

```bash
./build/issuer sign \
  -hardware ./hardware.json \
  -priv ./private.pem \
  -licensee "ACME Corp" \
  -not-after 2027-05-21 \
  -features pro,ai-camera \
  -max-offline-days 90 \
  -out license.json
```

#### 在被授权设备上本地签发（`-local`）

若私钥允许临时部署到设备（或通过 SSH 在 GB10 上执行），可跳过「导出 hardware.json → 内网签发 → 回传 license.json」步骤，由 `issuer` 在设备上**实时采集硬件**并直接写出 `license.json`。采集参数与 `hwinfo` / `verifier` 一致，指纹与验证器运行时完全对齐。

```bash
# 在 macOS 开发机上交叉编译设备端 issuer
make issuer-device

# 拷贝到 GB10 后，在宿主机上执行（按实际网卡/磁盘替换；需要 sudo 读取 DMI）
sudo ./build/issuer-device sign -local \
  -priv ./private.pem \
  -licensee "ACME Corp" \
  -not-after 2027-05-21 \
  -features pro,ai-camera \
  -max-offline-days 90 \
  -nic enP7s7 \
  -disk-name nvme0n1 \
  -require-gpu \
  -out ./license/license.json \
  -hardware-out ./license/hardware.json
```

`-local` 会默认再写一份 `hardware.json` 快照（可用 `-hardware-out` 改路径，`-` 表示不写）。在容器内签发时加 `-container`，使用 `/host/sys/...` 挂载路径（与 `docker-compose.yml` 一致）。

> **安全提示**：设备端签发意味着 `private.pem` 会出现在被授权设备上，仅在可控运维场景使用。常规部署仍推荐私钥只保留在内网主机。

`-not-after` 为必填项。`-max-offline-days 0`（默认）表示不启用离线时长限制；设为大于 0 的值时，设备必须在指定天数内完成一次有效验证，否则即使 `notAfter` 尚未到期，水位机制也会判定 License 失效。详见 [docs/max-offline-days.md](docs/max-offline-days.md)。

#### 签发并写入远端 MySQL（可选）

若需在内网签发后自动登记 License 台账，可使用 `scripts/issue-and-store.sh`。该脚本参数与 `issuer sign` 相同，签名成功后会调用 `build/licensedb` 将记录写入远端 MySQL，并把完整 `hardware.json` 存入 `hardware_remark` 字段作为备注。数据库或表不存在时会自动创建。

```bash
make issuer licensedb

export DB_HOST=10.191.147.1   # 远端 MySQL 地址
export DB_PORT=3306           # 默认 3306
export DB_USER=root
export DB_PASS='your-password'
export DB_NAME=hardware_license   # 可选，默认 hardware_license

./scripts/issue-and-store.sh \
  -hardware ./hardware.json \
  -priv ./private.pem \
  -licensee "ACME Corp" \
  -not-after 2027-05-21 \
  -features pro,ai-camera \
  -max-offline-days 90 \
  -out license.json
```

`licensedb` 使用 Go MySQL 驱动连接数据库，兼容远端仍使用 `mysql_native_password` 认证的服务器（Homebrew MySQL 9 CLI 已移除该插件，因此不再依赖 `mysql` 命令行客户端）。

写入表 `licenses` 的主要字段：`license_id`、`licensee`、有效期、`hardware_fingerprint`、`features`、`max_offline_days`、`note`、`hardware_remark`（完整 hardware.json）、`license_json`（完整 license.json）。同一 `license_id` 重复签发会更新已有记录。

### 4. 部署到设备

将 `license.json` 和 `public.pem` 放入设备宿主机的 `./license/` 目录，然后启动容器：

```bash
docker compose up -d app
```

`docker-compose.yml` 已将宿主机 `/sys` **整树**以只读方式挂载到 `/host/sys`（sysfs 内部的 symlink 要求整树挂载才能正确解析），同时挂载 `/proc/cmdline` 与 `/proc/driver/nvidia` → 容器内 `/host/nvidia-driver`（**不能**挂到容器 `/proc` 下，新版 Docker/runc 会拒绝）。

### 5. 运维侧快速校验

```bash
docker compose run --rm verifier -v
```

或在宿主机直接运行（与 `issuer sign -local` 相同，**需要 sudo** 以读取 DMI 字段；watermark 默认写在 license 同目录的 `.watermark`）：

```bash
sudo ./build/verifier -v \
  -pub ./public.pem \
  -license ./license.json \
  -nic enP7s7 \
  -disk-name nvme0n1 \
  -require-gpu
# 等价于 -watermark ./.watermark
```

---

## 文件说明

| 文件 | 创建者 | 使用者 | 生命周期 |
|------|--------|--------|----------|
| `private.pem` | `issuer keygen` | `issuer sign` | 永久（信任根） |
| `public.pem` | `issuer keygen` | `verifier`、Next.js 验证库 | 永久 |
| `hardware.json` | `hwinfo`（设备端） | `issuer sign` | 每台设备一份，硬件变更后需重新采集 |
| `license.json` | `issuer sign` | `verifier`、Next.js 验证库 | 至 `notAfter` 到期 |
| `.watermark` | 验证器（首次验证成功后） | 验证器（每次验证） | 每次验证后原子更新 |

---

## License 格式（v3）

```jsonc
{
  "version": 3,
  "id": "lic_<hex>",
  "issuedAt":  "2026-05-21T08:00:00Z",
  "notBefore": "2026-05-21T08:00:00Z",
  "notAfter":  "2027-05-21T23:59:59Z",
  "licensee": "ACME Corp",
  "hardwareFingerprint": "<sources 的 sha256 十六进制>",
  "encryptedPayload": {
    "alg": "AES-256-GCM",
    "nonce": "<base64>",
    "ciphertext": "<base64 ct||tag>"
  },
  "signature": "<base64 Ed25519，覆盖 canonical(license 除 signature 外所有字段)>"
}
```

明文载荷（加密前）会重复 `id` 和 `notAfter`，防止攻击者将其他 License 的密文拼接到当前头部：

```jsonc
{ "id": "...", "notAfter": "...", "features": [...], "maxOfflineDays": 90 }
```

---

## 验证流程（10 步）

按顺序执行：

1. 结构版本必须为 `3`
2. 对 canonical 后的 License 正文做 Ed25519 签名校验
3. 本地硬件指纹与 License 中的 `hardwareFingerprint` 一致
4. AES-256-GCM 载荷解密成功（内置认证标签）
5. 载荷内的 `id` / `notAfter` 与外层头部一致
6. 水位文件（若存在）HMAC 校验通过，且属于当前 License
7. 历史累计时间回拨次数 ≤ 3
8. `effectiveNow`（= `max(当前时间, watermark.lastSeenAt)`）落在 `[notBefore, notAfter]` 内
9. 自 `lastSeenAt` 起的真实墙钟间隔 ≤ `maxOfflineDays`（若已设置）
10. 更新水位文件并写入新的 HMAC

任一步失败均返回稳定的机器可读 `reason` 码；详细错误仅写入日志，不对外暴露。

**常见 `reason` 值：**

| reason | 含义 |
|--------|------|
| `ok` | 验证通过 |
| `malformed` | License 格式错误或损坏 |
| `unsupported_version` | 版本不匹配 |
| `signature_invalid` | 签名无效（可能被篡改） |
| `fingerprint_mismatch` | 硬件指纹不匹配 |
| `payload_mismatch` | 加密载荷与头部不一致 |
| `watermark_tampered` | 水位文件被篡改 |
| `time_rewind` | 系统时间回拨次数过多 |
| `not_yet_valid` | 尚未到生效时间 |
| `expired` | 已过期 |
| `offline_too_long` | 超过最大离线天数 |
| `hardware_unavailable` | 无法采集硬件信息 |

---

## 目录结构

```
hardware-license/
├── cmd/
│   ├── hwinfo/     # 设备端硬件采集（无密钥）
│   ├── issuer/     # 签发（内网读 hardware.json，或设备端 -local）
│   ├── licensedb/  # 签发台账写入远端 MySQL
│   └── verifier/   # 设备端验证 CLI（运维/调试）
├── scripts/
│   └── issue-and-store.sh   # issuer sign + licensedb store
├── internal/
│   └── license/    # Go 核心库（issuer 与 verifier 共用）
├── verifier-node/  # TypeScript 实现，供 Next.js 使用
│   ├── src/
│   └── test/       # 跨语言互通测试
├── examples/
│   └── nextjs/     # instrumentation.ts 集成示例
├── docs/
│   ├── hardware-fingerprint.md   # 硬件指纹采集与算法详解
│   ├── max-offline-days.md       # max-offline-days 参数说明与时序图
│   └── session-summary.md        # 会话关键信息汇总（GB10 指纹增强等）
├── Dockerfile      # 设备镜像（不含 private.pem）
├── docker-compose.yml
├── Makefile
└── README.md
```

> 详细的硬件采集字段、过滤规则、指纹算法、GB10 适配情况与排错指南，见 [`docs/hardware-fingerprint.md`](./docs/hardware-fingerprint.md)。

---

## Next.js 集成

1. 将 `verifier-node` 打包并安装到 Next.js 项目：

   ```bash
   cd verifier-node && npm run build && npm pack
   # 在 Next.js 项目中
   npm install ../verifier-node/yourorg-license-verifier-1.0.0.tgz
   ```

2. 将 `examples/nextjs/instrumentation.ts` 复制到 Next.js 项目根目录。

3. Next.js 13.x 需在 `next.config.js` 中启用 `experimental.instrumentationHook`（14+ 默认开启）。

4. 容器需挂载 `/license/` 及宿主机硬件路径，详见 `docker-compose.yml` 和 `examples/nextjs/README.md`。

---

## 安全运维须知

- `private.pem` 只存在于**一台**内网主机（条件允许时使用 HSM）。不得写入 Dockerfile、CI 或本仓库。
- 持有 `private.pem` 的人，可为任意已采集 `hardware.json` 的设备伪造 License。应像 CA 私钥一样严格保管。
- `public.pem` 可随设备镜像分发，也可提交到仓库。
- 若怀疑私钥泄露，需轮换密钥对并重新签发所有有效 License。本方案为离线设计，**不支持在线吊销**。
- `.watermark` 非机密，但完整性至关重要。删除后会重新初始化；在健康设备上无害，在已被篡改的设备上可能触发时间回拨检测。
- `max-offline-days` 用于强制定期续期：无人值守工业设备建议 180 天；需要更频繁接触客户的场景建议 30–60 天。原理与时序图见 [docs/max-offline-days.md](docs/max-offline-days.md)。
- `HW_NIC` 需提前确定并固定。指纹**不会**回退到「任意网卡」，这是有意为之的安全设计。

---

## 残留风险（需知情）

离线且攻击者可完全控制设备的场景下，任何离线 License 方案都无法做到 100% 防破解。攻击者仍可能通过逆向并 patch 验证逻辑绕过检查。

如需进一步加固，可考虑：

- 用 License 派生密钥**加密 Next.js 核心业务模块**（启动时解密再执行）
- 使用 `bytenode` / `pkg` 将 Node 业务代码编译为字节码
- 若 GB10 支持 ARM TrustZone，将验证逻辑放入 OP-TEE 可信执行环境

---

## GB10 部署前检查

在真实 GB10 环境签发 License 前，请分别于**宿主机**和**容器内**各运行一次 `hwinfo`，确认两次输出的 `fingerprint` **完全一致**。若不一致，请先调整 `docker-compose.yml` 的 volumes 挂载，再签发 License。

```bash
# 1) 宿主机直接采（GB10 真实网卡是 enP7s7，磁盘是 nvme0n1，按实际替换）
sudo ./build/hwinfo \
  -nic enP7s7 -disk-name nvme0n1 -require-gpu \
  -out hardware-host.json

# 2) 容器内采（挂载与 docker-compose.yml 一致 —— /sys 整树挂载）
docker run --rm \
  -v /sys:/host/sys:ro \
  -v /proc/cmdline:/host/cmdline:ro \
  -v /proc/driver/nvidia:/host/nvidia-driver:ro \
  --runtime=nvidia \
  -e NVIDIA_VISIBLE_DEVICES=all \
  -e NVIDIA_DRIVER_CAPABILITIES=utility \
  yourorg/hw-license:1.0.0 \
  /app/hwinfo \
    -nic enP7s7 -disk-name nvme0n1 \
    -dmi /host/sys/class/dmi/id \
    -net /host/sys/class/net \
    -block-dir /host/sys/class/block \
    -firmware-tree /host/sys/firmware/devicetree/base \
    -cmdline /host/cmdline \
    -require-gpu \
    -out -
```

`jq .sources` 比对两份输出，应**逐字段一致**；`fingerprint` 一致才能继续签发。
若 `disk_serial` 或 `host_mac` 在容器内为空、宿主机有值，几乎肯定是 bind-mount 错了（最常见错误：只挂 `/sys/class/net` 而没挂整树 `/sys`）。
