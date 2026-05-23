// Command issuer is the offline-license signing tool. It MUST run
// only on a trusted internal-network host. The private key it touches
// is the root of trust for the entire deployment; never copy it to a
// licensed device, a CI runner, or a developer laptop without a clear
// reason.
//
// Usage:
//
//	issuer keygen   -priv private.pem -pub public.pem
//	issuer sign     -hardware hardware.json -priv private.pem \
//	                -licensee "ACME Corp" \
//	                -not-after 2027-05-21 \
//	                -features pro,ai-camera \
//	                -max-offline-days 90 \
//	                -out license.json
//	issuer inspect  -license license.json [-pub public.pem] [-hardware hardware.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"license-service/internal/license"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "sign":
		cmdSign(os.Args[2:])
	case "inspect":
		cmdInspect(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "issuer: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `issuer — offline license issuer (Ed25519)

Subcommands:
  keygen    Generate an Ed25519 keypair (PKCS#8 / PKIX PEM).
  sign      Produce a license.json from a hardware.json.
  inspect   Pretty-print a license; if a public key is given,
            re-verify the signature. If a hardware.json is given,
            re-decrypt the payload.

Run 'issuer <subcommand> -h' for the per-command flags.
`)
}

// ---- keygen ----------------------------------------------------------------

func cmdKeygen(argv []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	priv := fs.String("priv", "private.pem", "output path for the private key (mode 0600)")
	pub := fs.String("pub", "public.pem", "output path for the public key (mode 0644)")
	force := fs.Bool("force", false, "overwrite existing key files")
	_ = fs.Parse(argv)

	if !*force {
		for _, p := range []string{*priv, *pub} {
			if _, err := os.Stat(p); err == nil {
				fail("%s already exists; pass -force to overwrite", p)
			}
		}
	}
	if err := license.GenerateEd25519Keypair(*priv, *pub); err != nil {
		fail("keygen: %v", err)
	}
	fmt.Printf("ed25519 keypair written:\n  private: %s (mode 0600)\n  public : %s (mode 0644)\n", *priv, *pub)
	fmt.Println("\nReminders:")
	fmt.Println("  * Keep the private key on this host only. Do NOT ship it inside any device image.")
	fmt.Println("  * Bundle the public key with the verifier (and with the Next.js app).")
}

// ---- sign ------------------------------------------------------------------

func cmdSign(argv []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	hwPath := fs.String("hardware", "hardware.json", "hardware.json from the device")
	privPath := fs.String("priv", "private.pem", "Ed25519 private key (PKCS#8 PEM)")
	out := fs.String("out", "license.json", "output license file")
	licensee := fs.String("licensee", "", "human-readable customer/licensee name (required)")
	notBefore := fs.String("not-before", "", "RFC3339 or YYYY-MM-DD; defaults to now (UTC)")
	notAfter := fs.String("not-after", "", "RFC3339 or YYYY-MM-DD; REQUIRED")
	features := fs.String("features", "", "comma-separated feature flags")
	maxOffline := fs.Int("max-offline-days", 0, "0 = unlimited; >0 = device must re-verify against fresh wall-clock within N days of LastSeenAt")
	note := fs.String("note", "", "free-form note stored inside the encrypted payload")
	force := fs.Bool("force", false, "overwrite existing license file")
	_ = fs.Parse(argv)

	if *licensee == "" {
		fail("sign: -licensee is required")
	}
	if *notAfter == "" {
		fail("sign: -not-after is required")
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fail("%s already exists; pass -force to overwrite", *out)
		}
	}

	hw, err := loadHardware(*hwPath)
	if err != nil {
		fail("sign: %v", err)
	}
	priv, err := license.LoadEd25519Private(*privPath)
	if err != nil {
		fail("sign: %v", err)
	}

	nbTime, err := parseDateOrTime(*notBefore, time.Time{})
	if err != nil {
		fail("sign: -not-before: %v", err)
	}
	naTime, err := parseDateOrTime(*notAfter, time.Time{})
	if err != nil {
		fail("sign: -not-after: %v", err)
	}
	if naTime.IsZero() {
		fail("sign: -not-after must be set")
	}
	// Bare dates resolve to 23:59:59 local-end-of-day for usability.
	if isBareDate(*notAfter) {
		naTime = endOfDayUTC(naTime)
	}

	feats := []string{}
	if *features != "" {
		for _, f := range strings.Split(*features, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				feats = append(feats, f)
			}
		}
	}

	lic, err := license.Issue(license.IssueOptions{
		Hardware:       hw,
		Licensee:       *licensee,
		NotBefore:      nbTime,
		NotAfter:       naTime,
		Features:       feats,
		MaxOfflineDays: *maxOffline,
		Note:           *note,
		PrivateKey:     priv,
	})
	if err != nil {
		fail("sign: %v", err)
	}

	if err := license.WriteJSONFileAtomic(*out, lic, 0o644); err != nil {
		fail("sign: write license: %v", err)
	}
	fmt.Printf("license written:\n  path:     %s\n  id:       %s\n  not-after: %s\n  features: %v\n",
		*out, lic.ID, lic.NotAfter.Format(time.RFC3339), feats)
}

// ---- inspect ---------------------------------------------------------------

func cmdInspect(argv []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	licPath := fs.String("license", "license.json", "license file to inspect")
	pubPath := fs.String("pub", "", "if set, re-verify Ed25519 signature with this key")
	hwPath := fs.String("hardware", "", "if set, derive AES key from this hardware.json and decrypt the payload")
	_ = fs.Parse(argv)

	var lic license.License
	if err := license.ReadJSONFileStrict(*licPath, &lic); err != nil {
		fail("inspect: %v", err)
	}

	out := map[string]any{
		"version":             lic.Version,
		"id":                  lic.ID,
		"issuedAt":            lic.IssuedAt,
		"notBefore":           lic.NotBefore,
		"notAfter":            lic.NotAfter,
		"licensee":            lic.Licensee,
		"hardwareFingerprint": lic.HardwareFingerprint,
	}

	if *pubPath != "" {
		pub, err := license.LoadEd25519Public(*pubPath)
		if err != nil {
			fail("inspect: %v", err)
		}
		if err := license.VerifySignature(pub, &lic); err != nil {
			out["signature"] = "INVALID: " + err.Error()
		} else {
			out["signature"] = "valid"
		}
	}

	if *hwPath != "" {
		hw, err := loadHardware(*hwPath)
		if err != nil {
			fail("inspect: %v", err)
		}
		if hw.Fingerprint != lic.HardwareFingerprint {
			out["payload"] = fmt.Sprintf("UNAVAILABLE: hardware fingerprint mismatch (hardware.json=%s, license=%s)",
				hw.Fingerprint, lic.HardwareFingerprint)
		} else {
			fpBytes, err := license.FingerprintBytes(hw.Fingerprint)
			if err != nil {
				fail("inspect: %v", err)
			}
			aes, err := license.DeriveKey(fpBytes, lic.ID, license.HKDFInfoPayloadKey)
			if err != nil {
				fail("inspect: %v", err)
			}
			payload, err := license.DecryptPayload(aes, lic.EncryptedPayload)
			if err != nil {
				out["payload"] = "UNDECRYPTABLE: " + err.Error()
			} else {
				out["payload"] = payload
			}
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// ---- helpers ---------------------------------------------------------------

func loadHardware(path string) (*license.HardwareInfo, error) {
	var hw license.HardwareInfo
	if err := license.ReadJSONFileStrict(path, &hw); err != nil {
		return nil, err
	}
	return &hw, nil
}

func parseDateOrTime(s string, zero time.Time) (time.Time, error) {
	if s == "" {
		return zero, nil
	}
	if isBareDate(s) {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return time.Time{}, err
		}
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

func isBareDate(s string) bool {
	return len(s) == 10 && s[4] == '-' && s[7] == '-'
}

func endOfDayUTC(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "issuer: "+format+"\n", args...)
	os.Exit(1)
}
