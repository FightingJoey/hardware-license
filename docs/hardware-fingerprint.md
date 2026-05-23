# 硬件指纹采集说明

本文档描述 `hwinfo` 工具在被授权设备上**实际采集的硬件信息**、**指纹计算算法**，以及在 GB10 等目标平台上的**适用情况**与**安全约束**。

> 相关代码：`internal/license/fingerprint.go`、`verifier-node/src/fingerprint.ts`。
> 两端实现必须**字节级一致**，否则同一台机器会得到不同的 fingerprint。

---

## 一、六类身份源

`hwinfo` 与设备端 `verifier` 共用同一份采集逻辑，按顺序逐项尝试，**采集到的项目**进入指纹计算，**未采集到的项目**自动跳过。

| 顺序 | source key | 数据来源（默认路径） | 适用平台 | 稳定性 |
|------|-----------|---------------------|----------|--------|
| 1 | `product_uuid` | `/sys/class/dmi/id/product_uuid` | x86 BIOS / 现代 UEFI 服务器 | 极高（BIOS 内置） |
| 1 | `product_serial` | `/sys/class/dmi/id/product_serial` | 同上 | 高 |
| 1 | `board_serial` | `/sys/class/dmi/id/board_serial` | 同上 | 高 |
| 1 | `dmi_sys_vendor` | `/sys/class/dmi/id/sys_vendor` | 所有 DMI | 厂商级（同型号一样） |
| 1 | `dmi_product_name` | `/sys/class/dmi/id/product_name` | 所有 DMI | 型号级（同型号一样） |
| 2 | `dt_serial_number` | `/proc/device-tree/serial-number`（回退 `/sys/firmware/devicetree/base/serial-number`） | **ARM SoC（Jetson / RPi 等）** | 极高（SoC 烧录） |
| 2 | `dt_model` | `/proc/device-tree/model`（同上回退） | 同上 | 极高 |
| 3 | `host_mac` | `/sys/class/net/<NIC>/address` | 所有 | 中等（须显式指定网卡名） |
| 4 | `root_uuid` | `/proc/cmdline` 中 `root=UUID=...` / `PARTUUID=...` | 所有 Linux | 高（重装/重新分区会变） |
| 5 | `disk_serial` | `/sys/class/block/<DISK>/device/serial` | 所有装有 NVMe/eMMC 的机器 | **极高（SSD 工厂序列号）** |
| 5 | `disk_wwid` | `/sys/class/block/<DISK>/wwid` | 同上 | 极高（NVMe EUI-64 / NGUID） |
| 6 | `gpu_uuid` | `nvidia-smi --query-gpu=uuid` → 回退 `/proc/driver/nvidia/gpus/*/information` | NVIDIA GPU（GB10 必有） | 极高（硬件烧录） |

> **OEM ARM 板的现实**：在 GB10/XFUSION FusionXpark 这类设备上，DMI 的 `product_uuid`/`*_serial` 字段几乎都是空的，device-tree 节点也可能完全不存在；这时 **`disk_serial` + `host_mac` + `gpu_uuid` 三件套**才是真正承担「绑定到这台机器」职责的源，缺一不可。

---

## 二、过滤与有效性判定

读到下列「无效占位值」**视同未采集**，不会进入指纹：

- 空字符串
- `N/A`
- `Not Specified`
- `Default string`（部分 OEM BIOS 默认占位）

特殊约束：

- **MAC 地址**：只采集 `-nic` / `HW_NIC` 指定的**单一网卡**，**不会**回退到任意网卡；零地址 `00:00:00:00:00:00` 也被过滤
- **GPU**：默认不存在时跳过；用 `-require-gpu` 或 `HW_REQUIRE_GPU=1` 可强制要求（推荐 GB10 启用）
- **`root_uuid`**：只接受 `UUID=` 或 `PARTUUID=` 形式，不接受 `root=/dev/sda1` 这种不稳定的设备路径
- **device-tree 节点**：尾部 NUL 字节会被截掉，保证 Go 与 Node 计算字节一致
- **块设备选择**：`-disk-name` / `HW_DISK` 显式指定（推荐 `nvme0n1`）；为空时按字典序自动选第一块 `nvme*n*`，回退 `mmcblk*`。指定的盘必须有可读的 `device/serial`，否则跳过
- **`disk_serial` 尾部空白**：内核会用空格把 serial 填到固定宽度，采集时一律 `TrimSpace`
- **所有源全空**：直接报错 `no hardware identity sources available`

---

## 三、指纹算法

```text
keys = sort(sources.keys())            # 按字典序

bytes = ""
for i, k in enumerate(keys):
    if i > 0:
        bytes += 0x1F                   # ASCII 单元分隔符（业务值中不可能出现）
    bytes += k + "=" + sources[k]

fingerprint = sha256(bytes).hex()
```

要点：

- **字典序排序**保证 Go 与 Node 输出一致
- **`0x1F` 分隔符**避免任何业务值产生歧义（控制字符不会出现在 UUID/MAC/序列号中）
- **SHA-256 十六进制**作为最终 fingerprint（64 字符）

---

## 四、输出格式

`hwinfo` 写出的 `hardware.json` 形如：

```json
{
  "schemaVersion": 1,
  "collectedAt": "2026-05-22T11:30:00Z",
  "platform": "linux/arm64",
  "nic": "eth0",
  "sources": {
    "board_serial": "...",
    "dt_model": "NVIDIA Grace Blackwell",
    "dt_serial_number": "...",
    "gpu_uuid": "GPU-xxxxx-...",
    "host_mac": "aa:bb:cc:dd:ee:ff",
    "product_uuid": "...",
    "root_uuid": "UUID:..."
  },
  "fingerprint": "<sha256 hex>"
}
```

字段说明：

| 字段 | 用途 |
|------|------|
| `schemaVersion` | 硬件信息结构版本号，未来字段变更时区分用 |
| `collectedAt` | 采集时刻（UTC，仅供运维审计） |
| `platform` | `runtime.GOOS + "/" + runtime.GOARCH`，仅信息性 |
| `nic` | 实际使用的网卡名（出问题时排查用） |
| `sources` | **原始**采集值，运维可以直接看出来「这是哪台机器」 |
| `fingerprint` | 真正参与签名绑定的 64 字符 SHA-256 |

签发 license 时 `issuer` 会**重新计算** `sources` 的指纹并和 `fingerprint` 字段比对，**两者不一致即拒绝签发**，防止客户端手工篡改 hardware.json 后骗取 license。

---

## 五、GB10 / FusionXpark 实测采集情况

下面是在 XFUSION FusionXpark GB10 上的实际诊断结果（用户提供）：

| source key | GB10 实测 | 备注 |
|-----------|-----------|------|
| `product_uuid` | ❌ 空 | OEM 出厂前被清掉 |
| `product_serial` / `board_serial` / `chassis_serial` | ❌ 空 | 同上 |
| `dmi_sys_vendor` | ✅ `XFUSION` | 仅厂商级 |
| `dmi_product_name` | ✅ `FusionXpark GB10` | 仅型号级 |
| `dt_serial_number` / `dt_model` | ❌ 不存在 | 该 BSP 未挂载 device-tree |
| `host_mac` | ✅ 例如 `44:1a:4c:07:52:fb` | **必须用真实网卡名 `enP7s7`**，不能用 `eth0` |
| `root_uuid` | ✅ 例如 `UUID:0c86507f-...` | 来自 `/proc/cmdline` |
| `disk_serial` | ✅ `511251124146000891` | **NVMe 工厂序列号，绑物理 SSD** |
| `disk_wwid` | ✅ `eui.0000000000000000...79a7b4ea30bc37` | **NVMe EUI-64，全球唯一** |
| `gpu_uuid` | ✅ `GPU-908ad27c-34ec-...` | 来自 `nvidia-smi -L` |

因此 GB10 实际能进入指纹的 sources 是这 **7 项**：

```
disk_serial, disk_wwid, dmi_product_name, dmi_sys_vendor,
gpu_uuid, host_mac, root_uuid
```

其中**真正承担「绑定到这一台机器」**的是：

1. `gpu_uuid` — 绑 GPU
2. `disk_serial` + `disk_wwid` — 绑 SSD（一对，互为校验）
3. `host_mac` — 绑物理网卡

只要 **GPU / SSD / 网卡** 任何一个被换，验证立即失败。剩下的 `dmi_*` 和 `root_uuid` 属于辅助/审计级别。

**经验法则**：在 GB10 上首次跑 `hwinfo`，应至少看到 **6 个以上** sources。低于 5 个说明：

1. bind-mount 没挂全（最常见，尤其漏 `/sys`）
2. 容器没装 nvidia runtime / 没传 `NVIDIA_DRIVER_CAPABILITIES=utility`
3. `-nic` 指定的网卡名错了（GB10 不是 `eth0`，要去 `ip link` 看）
4. `-disk-name` 指定的盘不存在或不是 NVMe

低熵指纹一律视为部署问题，需要先排查再批量签发。

---

## 六、CLI 使用

### 设备端裸机（GB10 推荐）

```bash
# 先看清楚网卡 / 磁盘真实名字
ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2}'
ls /sys/class/block | grep -E '^nvme[0-9]+n[0-9]+$'

# 采集
sudo ./build/hwinfo \
  -nic enP7s7 \
  -disk-name nvme0n1 \
  -require-gpu \
  -out hardware.json
```

### 设备端容器内（推荐做法）

```bash
docker run --rm \
  -v /sys:/host/sys:ro \
  -v /proc/cmdline:/host/cmdline:ro \
  -v /proc/driver/nvidia:/host/nvidia-driver:ro \
  --runtime=nvidia \
  -e NVIDIA_VISIBLE_DEVICES=all \
  -e NVIDIA_DRIVER_CAPABILITIES=utility \
  yourorg/hw-license:1.0.0 \
  /app/hwinfo \
    -nic enP7s7 \
    -disk-name nvme0n1 \
    -dmi /host/sys/class/dmi/id \
    -net /host/sys/class/net \
    -block-dir /host/sys/class/block \
    -firmware-tree /host/sys/firmware/devicetree/base \
    -cmdline /host/cmdline \
    -require-gpu \
    -out /tmp/hardware.json
```

> 注意 `/sys` 必须**整树挂载**（`-v /sys:/host/sys:ro`），不能只挂 `/sys/class/net` 或 `/sys/class/block` —— sysfs 内部用相对路径 symlink 指向 `/sys/devices/...`，部分挂载会导致 symlink 解析失败。

### 全部参数

| 参数 | 环境变量 | 默认值 | 说明 |
|------|---------|--------|------|
| `-out` | — | `hardware.json` | 输出路径，`-` 表示 stdout |
| `-nic` | `HW_NIC` | `eth0` | 参与指纹的网卡名（**GB10 用 `enP7s7`**） |
| `-dmi` | `HW_DMI` | `/sys/class/dmi/id` | DMI/SMBIOS 目录 |
| `-device-tree` | `HW_DT` | `/proc/device-tree` | ARM device-tree 目录（首选） |
| `-firmware-tree` | `HW_FW_TREE` | `/sys/firmware/devicetree/base` | device-tree sysfs 回退 |
| `-net` | `HW_NET` | `/sys/class/net` | 网卡目录根 |
| `-cmdline` | `HW_CMDLINE` | `/proc/cmdline` | 内核命令行文件 |
| `-block-dir` | `HW_BLOCK` | `/sys/class/block` | 块设备 sysfs 根，用于读 SSD serial/wwid |
| `-disk-name` | `HW_DISK` | *（自动选第一个 NVMe）* | 钉死某块盘，例如 `nvme0n1` |
| `-nvidia-smi` | `HW_NVIDIA_SMI` | `nvidia-smi` | nvidia-smi 路径，传空字符串可跳过 |
| `-require-gpu` | — | `false` | GPU UUID 不可用时直接报错 |
| `-print` | — | `false` | 同时把结果打印到 stdout |

---

## 七、安全设计要点

### 7.1 为什么必须显式指定网卡

容器内 `eth0` 默认是 Docker 创建的 veth，MAC 每次启动都不同；攻击者更可以用 `--mac-address` 任意伪造。本工具**强制**通过 `-nic` 指定一个**已知的宿主机网卡名**，并要求 docker-compose 通过 `network_mode: host` 或挂 `/sys/class/net` 让容器看到真实网卡，从而：

- 攻击者无法用 `--mac-address` 改变指定网卡的 MAC
- 拿不到固定 NIC 名的人无法伪造同一台机器的指纹

### 7.2 为什么 device-tree 节点要剥 NUL

`/proc/device-tree/*` 是内核暴露的 OF 节点，字符串以 NUL 结尾。Go `strings.TrimSpace` 不会去掉中间或尾部的 NUL，Node 端 `String.trim()` 也不会。两端实现**都必须**显式 `TrimRight("\x00")`，否则同一份 device-tree 在 Go 和 Node 端会算出不同的指纹。

### 7.3 为什么 root= 只接受 UUID/PARTUUID

`root=/dev/sda1` 这种设备路径会随磁盘枚举顺序变化（新插一块 NVMe 就会变），不能用作稳定标识。`root=UUID=xxx` 是 mkfs 时生成的 FS UUID，除非重新格式化根分区，否则永久稳定。

### 7.4 为什么 GPU 走双通道

- **优先 `nvidia-smi`**：兼容性最好，nvidia-container-runtime 暴露的就是这个命令
- **回退 nvidia proc 节点**：裸机读 `/proc/driver/nvidia`；容器内 bind-mount 到 `/host/nvidia-driver`（不可挂到容器 `/proc` 下）

两种渠道返回的 UUID 格式（`GPU-<uuid>`）一致，可以混用。

### 7.5 sha256 + 0x1F 分隔符

为什么不直接用 JSON canonical？因为：

- 指纹是**纯字节级**比较，不需要可读
- 0x1F（Unit Separator）作为分隔符，业务值（UUID/MAC/型号）中绝不会出现，没有歧义
- 比 JSON canonical 更轻量、跨语言更容易对齐

---

## 八、新增数据源的步骤

如果未来需要新增字段（例如 TPM EK、磁盘 WWN、CPU serial）：

1. 在 `internal/license/fingerprint.go` 的 `CollectSources()` 中加一条 `addIfNonEmpty(sources, "<key>", read…)`
2. 在 `verifier-node/src/fingerprint.ts` 的 `collectSources()` 中**同步**加一条
3. **不要**重命名已有 key：旧 license 会因指纹变化而失效
4. 加完后在 GB10 真机跑 `hwinfo`，确认两端 fingerprint 一致
5. 视情况升级 `HardwareInfo.SchemaVersion`（仅信息性，不影响 license 验证）

---

## 九、排错速查

| 现象 | 可能原因 |
|------|----------|
| `no hardware identity sources available` | bind-mount 没挂；或所有源都是 `N/A` |
| `gpu uuid required but unavailable` | 没启用 nvidia runtime；或 `-nvidia-smi` 路径错 |
| Go 和 Node fingerprint 不一致 | device-tree NUL 没剥；或某一端漏挂某个路径 |
| 容器与宿主机 fingerprint 不一致 | 容器内挂载和 hwinfo 参数不对应；最易遗漏 `/proc/cmdline` |
| 重启后 fingerprint 变了 | `eth0` 实际是 DHCP/虚拟接口；或操作员动了磁盘分区 |

排错命令：

```bash
# 比对宿主机 vs 容器内
./build/hwinfo -out - | jq .sources    # 宿主机直接跑
docker compose run --rm verifier ...   # 容器内跑同样的 hwinfo
```

两份 `sources` 必须**逐字段一致**，fingerprint 才会一致。
