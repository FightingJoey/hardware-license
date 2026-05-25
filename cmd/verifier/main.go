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
	licPath := flag.String("license", envOr("LICENSE_PATH", "/license/license.json"), "path to license.json")
	pubPath := flag.String("pub", envOr("LICENSE_PUBLIC_KEY", "/license/public.pem"), "path to Ed25519 public key (PEM)")
	watermarkPath := flag.String("watermark", envOr("LICENSE_WATERMARK", ""), "path to watermark file (default: .watermark beside -license)")
	container := flag.Bool("container", false, "force container bind-mount paths (/host/sys/...)")
	hostPaths := flag.Bool("host", false, "force bare-metal host paths (/sys/...)")
	nic := flag.String("nic", "", "host NIC name")
	dmiDir := flag.String("dmi", "", "DMI directory")
	dtDir := flag.String("device-tree", "", "ARM device-tree directory")
	fwTreeDir := flag.String("firmware-tree", "", "device-tree sysfs fallback")
	netDir := flag.String("net", "", "NIC directory root")
	cmdlinePath := flag.String("cmdline", "", "kernel cmdline file")
	blockDir := flag.String("block-dir", "", "block-device sysfs root")
	diskName := flag.String("disk-name", "", "pinned block device (e.g. nvme0n1)")
	nvidiaSMI := flag.String("nvidia-smi", "", "nvidia-smi binary (empty to skip)")
	requireGPU := flag.Bool("require-gpu", false, "fail if GPU UUID is unavailable")
	jsonOut := flag.Bool("json", false, "emit a JSON result to stdout (default: human-readable)")
	verbose := flag.Bool("v", false, "verbose: log internal diagnostics to stderr")
	flag.Parse()

	wmPath := *watermarkPath
	if wmPath == "" {
		wmPath = license.DefaultWatermarkPath(*licPath)
	}

	pub, err := license.LoadEd25519Public(*pubPath)
	if err != nil {
		fatalf("read public key: %v", err)
	}

	var forceContainer *bool
	switch {
	case *container && *hostPaths:
		fatalf("use either -container or -host, not both")
	case *container:
		t := true
		forceContainer = &t
	case *hostPaths:
		f := false
		forceContainer = &f
	}

	fpCfg := license.FingerprintConfigFromEnv(forceContainer)
	explicit := visitedFlags()
	var reqGPU *bool
	if explicit["require-gpu"] {
		reqGPU = requireGPU
	}
	fpCfg = license.ApplyFingerprintFlags(fpCfg, nic, dmiDir, dtDir, fwTreeDir, netDir, cmdlinePath, blockDir, diskName, nvidiaSMI, reqGPU)

	if *verbose {
		fmt.Fprintf(os.Stderr, "[verify] fingerprint paths: dmi=%s net=%s block=%s cmdline=%s fw=%s nic=%s disk=%s\n",
			fpCfg.DMIDir, fpCfg.NetDir, fpCfg.BlockDir, fpCfg.CmdlinePath, fpCfg.FirmwareTreeDir, fpCfg.NICName, fpCfg.DiskName)
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
		WatermarkPath: wmPath,
		Fingerprint:   fpCfg,
		Logger:        logger,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		if res.Valid {
			fmt.Printf("license: VALID\n  id:        %s\n", res.LicenseID)
			if res.NotAfter != nil {
				fmt.Printf("  notAfter:  %s\n", res.NotAfter.Format(time.RFC3339))
				if res.DaysLeft != nil {
					fmt.Printf("  daysLeft:  %d\n", *res.DaysLeft)
				}
			} else {
				fmt.Printf("  notAfter:  <permanent>\n  daysLeft:  ∞\n")
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

func visitedFlags() map[string]bool {
	m := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		m[f.Name] = true
	})
	return m
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verifier: "+format+"\n", args...)
	os.Exit(3)
}
