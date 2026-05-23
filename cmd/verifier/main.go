// Command verifier is a thin CLI wrapper around license.Verify(). It
// is intended for operators and automated tests; in production the
// authoritative verifier is the in-process Node library bundled with
// the Next.js app. We ship this binary anyway so that ops can sanity-
// check a deployment without booting the full app.
//
// Exit codes:
//
//	0  license valid
//	2  license invalid (see stdout JSON for reason)
//	3  unexpected error (I/O, malformed config, etc.)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"license-service/internal/license"
)

func main() {
	var (
		licPath       = flag.String("license", envOr("LICENSE_PATH", "/license/license.json"), "path to license.json")
		pubPath       = flag.String("pub", envOr("LICENSE_PUBLIC_KEY", "/license/public.pem"), "path to Ed25519 public key (PEM)")
		watermarkPath = flag.String("watermark", envOr("LICENSE_WATERMARK", "/license/.watermark"), "path to the watermark file")
		nic           = flag.String("nic", envOr("HW_NIC", "eth0"), "host NIC name")
		dmiDir        = flag.String("dmi", envOr("HW_DMI", "/host/sys/class/dmi/id"), "DMI directory (host bind-mount)")
		dtDir         = flag.String("device-tree", envOr("HW_DT", "/proc/device-tree"), "ARM device-tree directory (preferred)")
		fwTreeDir     = flag.String("firmware-tree", envOr("HW_FW_TREE", "/host/sys/firmware/devicetree/base"), "device-tree sysfs fallback")
		netDir        = flag.String("net", envOr("HW_NET", "/host/sys/class/net"), "NIC directory root")
		cmdlinePath   = flag.String("cmdline", envOr("HW_CMDLINE", "/host/cmdline"), "kernel cmdline file")
		blockDir      = flag.String("block-dir", envOr("HW_BLOCK", "/host/sys/class/block"), "block-device sysfs root")
		diskName      = flag.String("disk-name", envOr("HW_DISK", ""), "pinned block device (e.g. nvme0n1); empty = auto-pick")
		nvidiaSMI     = flag.String("nvidia-smi", envOr("HW_NVIDIA_SMI", "nvidia-smi"), "nvidia-smi binary (empty to skip)")
		requireGPU    = flag.Bool("require-gpu", envBool("HW_REQUIRE_GPU"), "fail if GPU UUID is unavailable")
		jsonOut       = flag.Bool("json", false, "emit a JSON result to stdout (default: human-readable)")
		verbose       = flag.Bool("v", false, "verbose: log internal diagnostics to stderr")
	)
	flag.Parse()

	pub, err := license.LoadEd25519Public(*pubPath)
	if err != nil {
		fatalf("read public key: %v", err)
	}

	var logger func(license.VerifyEvent)
	if *verbose {
		logger = func(ev license.VerifyEvent) {
			fmt.Fprintf(os.Stderr, "[verify] reason=%s license=%s fp=%s now=%s eff=%s",
				ev.Reason, ev.LicenseID, ev.Fingerprint,
				ev.Now.Format(time.RFC3339), ev.Effective.Format(time.RFC3339))
			if ev.Err != nil {
				fmt.Fprintf(os.Stderr, " err=%v", ev.Err)
			}
			fmt.Fprintln(os.Stderr)
		}
	}

	res := license.Verify(license.VerifyOptions{
		LicensePath:   *licPath,
		PublicKey:     pub,
		WatermarkPath: *watermarkPath,
		Fingerprint: license.FingerprintConfig{
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
		},
		Logger: logger,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		if res.Valid {
			daysLeft := -1
			if res.DaysLeft != nil {
				daysLeft = *res.DaysLeft
			}
			fmt.Printf("license: VALID\n  id:        %s\n  daysLeft:  %d\n", res.LicenseID, daysLeft)
			if res.NotAfter != nil {
				fmt.Printf("  notAfter:  %s\n", res.NotAfter.Format(time.RFC3339))
			}
			if len(res.Features) > 0 {
				fmt.Printf("  features:  %v\n", res.Features)
			}
		} else {
			fmt.Printf("license: INVALID (%s)\n", res.Reason)
		}
	}

	if !res.Valid {
		os.Exit(2)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool {
	v := os.Getenv(k)
	return v == "1" || v == "true" || v == "yes"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verifier: "+format+"\n", args...)
	os.Exit(3)
}
