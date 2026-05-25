package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// IssueOptions are the inputs the issuer receives from the operator
// (CLI flags) plus the customer-supplied HardwareInfo.
type IssueOptions struct {
	Hardware  *HardwareInfo
	Licensee  string
	NotBefore time.Time // optional; defaults to now
	// NotAfter is required when Permanent=false; ignored otherwise.
	NotAfter time.Time
	// Permanent issues a license that never expires. NotAfter is forced
	// to the zero time and MaxOfflineDays is forced to 0. Hardware
	// fingerprint, signature and watermark protections still apply.
	Permanent      bool
	Features       []string
	MaxOfflineDays int
	Note           string
	PrivateKey     ed25519.PrivateKey
	// IDOverride lets tests pin the license ID; production callers
	// must leave this empty so a fresh random ID is generated.
	IDOverride string
}

// Issue produces a fully-signed License. It does NOT touch the disk.
func Issue(opts IssueOptions) (*License, error) {
	if opts.Hardware == nil {
		return nil, fmt.Errorf("issue: missing hardware info")
	}
	if opts.Hardware.Fingerprint == "" {
		return nil, fmt.Errorf("issue: hardware info has empty fingerprint")
	}
	// Recompute the fingerprint from the supplied sources and refuse to
	// proceed if it disagrees with what the customer claimed. This
	// catches both honest mistakes and outright tampering of the
	// hardware.json file.
	recomputed, err := ComputeFingerprint(opts.Hardware.Sources)
	if err != nil {
		return nil, fmt.Errorf("issue: recompute fingerprint: %w", err)
	}
	if recomputed != opts.Hardware.Fingerprint {
		return nil, fmt.Errorf("issue: hardware.json fingerprint mismatch (got %s, recomputed %s)", opts.Hardware.Fingerprint, recomputed)
	}
	if opts.Permanent {
		if !opts.NotAfter.IsZero() {
			return nil, fmt.Errorf("issue: permanent license must not have notAfter")
		}
		if opts.MaxOfflineDays != 0 {
			return nil, fmt.Errorf("issue: permanent license must have maxOfflineDays=0")
		}
	} else {
		if opts.NotAfter.IsZero() {
			return nil, fmt.Errorf("issue: notAfter is required (or pass Permanent=true)")
		}
		if !opts.NotBefore.IsZero() && !opts.NotAfter.After(opts.NotBefore) {
			return nil, fmt.Errorf("issue: notAfter must be > notBefore")
		}
	}
	if opts.MaxOfflineDays < 0 {
		return nil, fmt.Errorf("issue: maxOfflineDays must be >= 0")
	}
	if opts.PrivateKey == nil {
		return nil, fmt.Errorf("issue: missing private key")
	}

	now := time.Now().UTC().Truncate(time.Second)
	nb := opts.NotBefore.UTC()
	if nb.IsZero() {
		nb = now
	}
	// For permanent licenses na is the zero time, which JSON-serialises
	// to "0001-01-01T00:00:00Z" deterministically on Go and Node.
	na := opts.NotAfter.UTC()

	id := opts.IDOverride
	if id == "" {
		var buf [16]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("issue: rand: %w", err)
		}
		// Lightweight UUIDv4-ish; we don't actually need RFC 4122 bits
		// because the ID is only consumed by our own code.
		id = "lic_" + hex.EncodeToString(buf[:])
	}

	fpBytes, err := FingerprintBytes(opts.Hardware.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("issue: fingerprint bytes: %w", err)
	}
	aesKey, err := DeriveKey(fpBytes, id, HKDFInfoPayloadKey)
	if err != nil {
		return nil, fmt.Errorf("issue: derive key: %w", err)
	}
	defer zero(aesKey)

	features := opts.Features
	if features == nil {
		features = []string{}
	}
	expires := !opts.Permanent
	payload := &Payload{
		ID:             id,
		Expires:        expires,
		NotAfter:       na,
		Features:       features,
		MaxOfflineDays: opts.MaxOfflineDays,
		Note:           opts.Note,
	}
	enc, err := EncryptPayload(aesKey, payload)
	if err != nil {
		return nil, fmt.Errorf("issue: encrypt payload: %w", err)
	}

	lic := &License{
		Version:             FormatVersion,
		ID:                  id,
		IssuedAt:            now,
		NotBefore:           nb,
		NotAfter:            na,
		Expires:             expires,
		Licensee:            opts.Licensee,
		HardwareFingerprint: opts.Hardware.Fingerprint,
		EncryptedPayload:    enc,
	}
	if err := SignLicense(opts.PrivateKey, lic); err != nil {
		return nil, fmt.Errorf("issue: sign: %w", err)
	}
	return lic, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
