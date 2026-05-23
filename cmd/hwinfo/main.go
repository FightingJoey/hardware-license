// Command hwinfo collects host hardware identity sources and writes
// them as hardware.json. This tool does NOT carry any keys; it is safe
// to ship on the licensed device.
//
// The output file is then sent (out of band) to the issuer team, who
// turns it into license.json using `issuer sign`.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"license-service/internal/license"
)

func main() {
	var (
		outPath     = flag.String("out", "hardware.json", "output file (use - for stdout)")
		nic         = flag.String("nic", envOr("HW_NIC", "eth0"), "host NIC name whose MAC participates in the fingerprint")
		dmiDir      = flag.String("dmi", envOr("HW_DMI", "/sys/class/dmi/id"), "DMI/SMBIOS directory")
		dtDir       = flag.String("device-tree", envOr("HW_DT", "/proc/device-tree"), "ARM device-tree directory (preferred)")
		fwTreeDir   = flag.String("firmware-tree", envOr("HW_FW_TREE", "/sys/firmware/devicetree/base"), "device-tree sysfs fallback")
		netDir      = flag.String("net", envOr("HW_NET", "/sys/class/net"), "NIC directory root")
		cmdlinePath = flag.String("cmdline", envOr("HW_CMDLINE", "/proc/cmdline"), "kernel cmdline file")
		blockDir    = flag.String("block-dir", envOr("HW_BLOCK", "/sys/class/block"), "block-device sysfs root (for disk serial/wwid)")
		diskName    = flag.String("disk-name", envOr("HW_DISK", ""), "pinned block device (e.g. nvme0n1); empty = auto-pick first NVMe")
		nvidiaSMI   = flag.String("nvidia-smi", envOr("HW_NVIDIA_SMI", "nvidia-smi"), "nvidia-smi binary (empty to skip)")
		requireGPU  = flag.Bool("require-gpu", false, "fail if GPU UUID is unavailable")
		showOnly    = flag.Bool("print", false, "also print the result to stdout")
	)
	flag.Parse()

	cfg := license.FingerprintConfig{
		DMIDir:          *dmiDir,
		DeviceTreeDir:   *dtDir,
		FirmwareTreeDir: *fwTreeDir,
		NetDir:          *netDir,
		NICName:         *nic,
		CmdlinePath:     *cmdlinePath,
		BlockDir:        *blockDir,
		DiskName:        *diskName,
		NvidiaSMI:       *nvidiaSMI,
		RequireGPU:      *requireGPU,
	}

	info, err := license.CollectHardwareInfo(cfg)
	if err != nil {
		fail("collect hardware info: %v", err)
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fail("marshal: %v", err)
	}
	data = append(data, '\n')

	if *outPath == "-" {
		os.Stdout.Write(data)
	} else {
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			fail("write %s: %v", *outPath, err)
		}
		fmt.Fprintf(os.Stderr, "hardware.json written to %s\nfingerprint: %s\nsources: %d\n",
			*outPath, info.Fingerprint, len(info.Sources))
		if *showOnly {
			os.Stdout.Write(data)
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hwinfo: "+format+"\n", args...)
	os.Exit(1)
}
