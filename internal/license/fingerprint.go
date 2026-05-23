package license

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FingerprintConfig points the collector at host-side filesystem
// mounts. Inside a container, /sys and /proc reflect the namespace,
// so we bind-mount the host's sysfs and procfs at fixed paths.
//
// Recommended docker-compose volumes:
//
//	volumes:
//	  - /sys:/host/sys:ro
//	  - /proc/cmdline:/host/cmdline:ro
//	  - /proc/driver/nvidia:/proc/driver/nvidia:ro
//
// Mounting the entire /sys (read-only) is required because sysfs uses
// internal symlinks (e.g. /sys/class/net/eth0 -> ../../devices/...)
// which only resolve correctly when the whole tree is visible inside
// the container. The verifier and hwinfo MUST share the exact same
// FingerprintConfig.
type FingerprintConfig struct {
	// DMIDir is /sys/class/dmi/id (or its host bind-mount). On ARM
	// OEM boards (e.g. XFUSION GB10) the serial fields are usually
	// empty; only sys_vendor / product_name come back populated.
	DMIDir string
	// DeviceTreeDir is /proc/device-tree (preferred) — usually present
	// on Tegra/Jetson/RPi platforms.
	DeviceTreeDir string
	// FirmwareTreeDir is /sys/firmware/devicetree/base, the sysfs
	// fallback for kernels that no longer expose /proc/device-tree
	// or systems that boot via ACPI.
	FirmwareTreeDir string
	// NetDir is /sys/class/net (root of NIC entries).
	NetDir string
	// NICName is the host NIC whose MAC participates in the fingerprint
	// (e.g. "eth0", "enP7s7"). Pinning the name prevents an attacker
	// from picking a random veth or USB adapter.
	NICName string
	// CmdlinePath is /proc/cmdline; used to extract the root= UUID.
	CmdlinePath string
	// BlockDir is /sys/class/block. The most stable identity source
	// on OEM ARM systems where DMI serials come blank — NVMe SSDs
	// always carry a factory serial in <BlockDir>/<dev>/device/serial.
	BlockDir string
	// DiskName pins a specific block device (e.g. "nvme0n1"). When
	// empty the collector picks the lexicographically-first NVMe
	// namespace, falling back to the first eMMC.
	DiskName string
	// NvidiaSMI is the path to nvidia-smi if available. Optional; the
	// GPU UUID source falls back to /proc/driver/nvidia parsing.
	NvidiaSMI string
	// RequireGPU forces failure when GPU UUID is unreadable. Set true
	// on devices that are supposed to have an NVIDIA GPU (like GB10).
	RequireGPU bool
}

// DefaultLinuxConfig returns the recommended layout for a Linux device
// where the verifier runs inside a container with /sys bind-mounted
// read-only at /host/sys. See FingerprintConfig comment for the
// docker-compose snippet.
func DefaultLinuxConfig() FingerprintConfig {
	return FingerprintConfig{
		DMIDir:          "/host/sys/class/dmi/id",
		DeviceTreeDir:   "/proc/device-tree",
		FirmwareTreeDir: "/host/sys/firmware/devicetree/base",
		NetDir:          "/host/sys/class/net",
		NICName:         firstEnv("HW_NIC", "eth0"),
		CmdlinePath:     "/host/cmdline",
		BlockDir:        "/host/sys/class/block",
		DiskName:        os.Getenv("HW_DISK"),
		NvidiaSMI:       "nvidia-smi",
		RequireGPU:      false,
	}
}

func firstEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// CollectSources gathers every available identity source. Sources that
// are not available are simply omitted from the map; callers decide
// whether to treat missing sources as fatal.
//
// The map keys are stable identifiers; do NOT rename them or you break
// existing licenses.
func CollectSources(cfg FingerprintConfig) (map[string]string, error) {
	sources := map[string]string{}

	// 1) x86_64 DMI / SMBIOS — every server/workstation BIOS fills these.
	//    Per-device:
	addIfNonEmpty(sources, "product_uuid", readTrimmed(filepath.Join(cfg.DMIDir, "product_uuid")))
	addIfNonEmpty(sources, "product_serial", readTrimmed(filepath.Join(cfg.DMIDir, "product_serial")))
	addIfNonEmpty(sources, "board_serial", readTrimmed(filepath.Join(cfg.DMIDir, "board_serial")))
	//    Model-level (OEM brand + product family). On ARM OEMs these
	//    are often the only populated DMI fields; they don't add
	//    per-unit entropy but they refuse to validate when the license
	//    is moved between different product lines.
	addIfNonEmpty(sources, "dmi_sys_vendor", readTrimmed(filepath.Join(cfg.DMIDir, "sys_vendor")))
	addIfNonEmpty(sources, "dmi_product_name", readTrimmed(filepath.Join(cfg.DMIDir, "product_name")))

	// 2) ARM SoC device tree — typical on Tegra Jetson / RPi. Newer
	//    kernels (and some Grace boards) drop /proc/device-tree, so we
	//    also try the sysfs path /sys/firmware/devicetree/base.
	addIfNonEmpty(sources, "dt_serial_number",
		firstNonEmpty(
			readTrimmedNullStripped(filepath.Join(cfg.DeviceTreeDir, "serial-number")),
			readTrimmedNullStripped(filepath.Join(cfg.FirmwareTreeDir, "serial-number")),
		))
	addIfNonEmpty(sources, "dt_model",
		firstNonEmpty(
			readTrimmedNullStripped(filepath.Join(cfg.DeviceTreeDir, "model")),
			readTrimmedNullStripped(filepath.Join(cfg.FirmwareTreeDir, "model")),
		))

	// 3) Pinned host NIC. We require an explicit name so attackers can't
	//    swap in another adapter. We refuse to fall back to "first NIC".
	if cfg.NICName != "" {
		if mac := readTrimmed(filepath.Join(cfg.NetDir, cfg.NICName, "address")); mac != "" && mac != "00:00:00:00:00:00" {
			sources["host_mac"] = strings.ToLower(mac)
		}
	}

	// 4) Root filesystem UUID from kernel cmdline. Stable across reboots
	//    but not across re-installs; treat as auxiliary, not primary.
	if uuid := extractRootUUID(readTrimmed(cfg.CmdlinePath)); uuid != "" {
		sources["root_uuid"] = uuid
	}

	// 5) Block-device identity. The strongest source on OEM ARM boards
	//    where DMI serials come blank — NVMe SSDs always carry a stable
	//    factory serial and (usually) an EUI-64 / NGUID wwid.
	if disk := chooseBlockDevice(cfg); disk != "" {
		addIfNonEmpty(sources, "disk_serial",
			readTrimmed(filepath.Join(cfg.BlockDir, disk, "device", "serial")))
		addIfNonEmpty(sources, "disk_wwid",
			readTrimmed(filepath.Join(cfg.BlockDir, disk, "wwid")))
	}

	// 6) GPU UUID (NVIDIA only). Two ways: nvidia-smi (preferred, works
	//    in containers with the nvidia runtime) or the proc node.
	if uuid := queryGPUUUID(cfg); uuid != "" {
		sources["gpu_uuid"] = uuid
	} else if cfg.RequireGPU {
		return nil, fmt.Errorf("gpu uuid required but unavailable")
	}

	if len(sources) == 0 {
		return nil, errors.New("no hardware identity sources available")
	}
	return sources, nil
}

// ComputeFingerprint serialises the sources map with deterministic
// ordering and returns sha256(canonical) as hex.
func ComputeFingerprint(sources map[string]string) (string, error) {
	if len(sources) == 0 {
		return "", errors.New("empty sources")
	}
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for i, k := range keys {
		if i > 0 {
			h.Write([]byte{0x1f}) // ASCII unit-separator, never appears in our values
		}
		h.Write([]byte(k))
		h.Write([]byte{0x3d}) // '='
		h.Write([]byte(sources[k]))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CollectHardwareInfo is the one-stop call used by `hwinfo` and the
// verifier alike. It returns the full HardwareInfo struct ready to be
// serialized.
func CollectHardwareInfo(cfg FingerprintConfig) (*HardwareInfo, error) {
	sources, err := CollectSources(cfg)
	if err != nil {
		return nil, err
	}
	fp, err := ComputeFingerprint(sources)
	if err != nil {
		return nil, err
	}
	return &HardwareInfo{
		SchemaVersion: 1,
		CollectedAt:   time.Now().UTC(),
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		NIC:           cfg.NICName,
		Sources:       sources,
		Fingerprint:   fp,
	}, nil
}

// --- internals ---------------------------------------------------------

var (
	nvmeNamespaceRe = regexp.MustCompile(`^nvme\d+n\d+$`)
	mmcDeviceRe     = regexp.MustCompile(`^mmcblk\d+$`)
)

// chooseBlockDevice returns the basename of the block device whose
// `device/serial` will be hashed into the fingerprint. Selection rules:
//
//   1. If cfg.DiskName is set, use it iff its serial node is readable.
//   2. Otherwise pick the lexicographically-first nvme*n* entry.
//   3. Failing that, the first mmcblk* entry.
//
// Empty string means "no block-device source available"; the caller
// will silently omit the disk_serial / disk_wwid entries.
func chooseBlockDevice(cfg FingerprintConfig) string {
	if cfg.BlockDir == "" {
		return ""
	}
	if cfg.DiskName != "" {
		if _, err := os.Stat(filepath.Join(cfg.BlockDir, cfg.DiskName, "device", "serial")); err == nil {
			return cfg.DiskName
		}
		return ""
	}
	entries, err := os.ReadDir(cfg.BlockDir)
	if err != nil {
		return ""
	}
	var nvmes, mmcs []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case nvmeNamespaceRe.MatchString(name):
			nvmes = append(nvmes, name)
		case mmcDeviceRe.MatchString(name):
			mmcs = append(mmcs, name)
		}
	}
	sort.Strings(nvmes)
	sort.Strings(mmcs)
	for _, candidate := range append(nvmes, mmcs...) {
		// Confirm the serial node is actually readable before committing.
		if _, err := os.Stat(filepath.Join(cfg.BlockDir, candidate, "device", "serial")); err == nil {
			return candidate
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func addIfNonEmpty(m map[string]string, key, val string) {
	val = strings.TrimSpace(val)
	if val == "" || val == "N/A" || val == "Not Specified" || val == "Default string" {
		return
	}
	m[key] = val
}

func readTrimmed(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readTrimmedNullStripped is for device-tree nodes which terminate
// strings with a NUL byte.
func readTrimmedNullStripped(path string) string {
	s := readTrimmed(path)
	return strings.TrimRight(s, "\x00")
}

// extractRootUUID parses kernel cmdline for `root=UUID=xxx` or
// `root=PARTUUID=xxx`. We don't accept bare device paths because they
// aren't stable identifiers.
func extractRootUUID(cmdline string) string {
	for _, tok := range strings.Fields(cmdline) {
		if !strings.HasPrefix(tok, "root=") {
			continue
		}
		v := strings.TrimPrefix(tok, "root=")
		if strings.HasPrefix(v, "UUID=") {
			return "UUID:" + strings.TrimPrefix(v, "UUID=")
		}
		if strings.HasPrefix(v, "PARTUUID=") {
			return "PARTUUID:" + strings.TrimPrefix(v, "PARTUUID=")
		}
	}
	return ""
}

func queryGPUUUID(cfg FingerprintConfig) string {
	if cfg.NvidiaSMI != "" {
		ctx, cancel := commandWithTimeout(3 * time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, cfg.NvidiaSMI, "--query-gpu=uuid", "--format=csv,noheader").Output()
		if err == nil {
			first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			if first != "" {
				return strings.TrimSpace(first)
			}
		}
	}
	// Fallback: /proc/driver/nvidia/gpus/*/information contains a GPU UUID line.
	matches, _ := filepath.Glob("/proc/driver/nvidia/gpus/*/information")
	for _, p := range matches {
		data := readTrimmed(p)
		for _, line := range strings.Split(data, "\n") {
			if strings.HasPrefix(line, "GPU UUID:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "GPU UUID:"))
			}
		}
	}
	return ""
}
