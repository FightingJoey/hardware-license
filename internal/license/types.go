// Package license implements the v3 offline license format:
// Ed25519 signature + AES-256-GCM payload + HKDF key derivation,
// bound to multi-source host hardware identity and a tamper-evident
// monotonic time watermark.
package license

import "time"

// FormatVersion is the current license schema version. Verifiers MUST
// refuse any license whose version does not match exactly.
//
// v4 (this revision) introduces the explicit `Expires` flag. When set
// to false the license is permanent: NotAfter is the zero time, and the
// expired / offline_too_long checks are skipped. The hardware
// fingerprint and tamper-evidence (watermark, time-rewind, signature)
// checks remain in force regardless.
const FormatVersion = 4

// HKDF info strings used to derive distinct keys from the host
// fingerprint bytes. Both ends MUST use the exact same constants.
const (
	HKDFInfoPayloadKey   = "license-v3:payload-aes-gcm"
	HKDFInfoWatermarkKey = "license-v3:watermark-hmac"
)

// HardwareInfo is produced on the licensed device by `hwinfo` and
// consumed by the issuer. It must contain every source that will
// participate in the fingerprint, so that the issuer can re-derive
// the exact same value the verifier will compute at runtime.
//
// Sources MUST be alphabetically ordered when serialized for the
// fingerprint (see CanonicalJSON / ComputeFingerprint).
type HardwareInfo struct {
	SchemaVersion int               `json:"schemaVersion"`
	CollectedAt   time.Time         `json:"collectedAt"`
	Platform      string            `json:"platform"` // e.g. "linux/arm64"
	NIC           string            `json:"nic"`      // host NIC name used for MAC
	Sources       map[string]string `json:"sources"`
	Fingerprint   string            `json:"fingerprint"` // sha256 hex of canonical(sources)
}

// EncryptedPayload is the AES-256-GCM ciphertext of the inner Payload.
// Nonce and Ciphertext are base64 (standard, no padding stripping).
type EncryptedPayload struct {
	Alg        string `json:"alg"`        // always "AES-256-GCM"
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64 (includes GCM tag)
}

// License is the on-disk format written to /license/license.json on the
// device. Every field except Signature participates in the signature.
// Verifiers MUST reject any unknown field.
type License struct {
	Version             int              `json:"version"`
	ID                  string           `json:"id"`                  // ULID
	IssuedAt            time.Time        `json:"issuedAt"`            // UTC
	NotBefore           time.Time        `json:"notBefore"`           // UTC
	NotAfter            time.Time        `json:"notAfter"`            // UTC; zero when Expires=false
	Expires             bool             `json:"expires"`             // false → permanent license, NotAfter ignored
	Licensee            string           `json:"licensee"`
	HardwareFingerprint string           `json:"hardwareFingerprint"` // sha256 hex
	EncryptedPayload    EncryptedPayload `json:"encryptedPayload"`
	Signature           string           `json:"signature"` // base64 ed25519 of canonical(license without signature)
}

// Payload is the plaintext inside EncryptedPayload. It re-states ID,
// Expires and NotAfter to defeat "header swap" attacks where an
// attacker tries to glue someone else's encrypted payload onto a
// license header — in particular, swapping a permanent payload onto a
// time-limited header (or vice versa) is detected by the cross-bind.
type Payload struct {
	ID             string    `json:"id"`             // must equal License.ID
	Expires        bool      `json:"expires"`        // must equal License.Expires
	NotAfter       time.Time `json:"notAfter"`       // must equal License.NotAfter (zero when !Expires)
	Features       []string  `json:"features"`
	MaxOfflineDays int       `json:"maxOfflineDays"` // 0 = unlimited; forced to 0 when !Expires
	Note           string    `json:"note,omitempty"`
}

// Watermark is the tamper-evident monotonic clock stored on the device.
// It is HMAC-protected with a key derived from the host fingerprint so
// it cannot be forged or transplanted to another machine.
type Watermark struct {
	LicenseID       string    `json:"licenseId"`
	FirstSeenAt     time.Time `json:"firstSeenAt"`     // UTC
	LastSeenAt      time.Time `json:"lastSeenAt"`      // UTC, monotonic
	VerifyCount     uint64    `json:"verifyCount"`
	TimeRewindCount uint64    `json:"timeRewindCount"`
	MAC             string    `json:"mac"` // base64 HMAC-SHA256 of canonical(watermark without mac)
}

// VerifyReason is a stable machine-readable error code. Verifiers MUST
// NOT expose the underlying error details outside the host process;
// only this code is safe to return to callers.
type VerifyReason string

const (
	ReasonOK                 VerifyReason = "ok"
	ReasonMalformed          VerifyReason = "malformed"
	ReasonUnsupportedVersion VerifyReason = "unsupported_version"
	ReasonSignatureInvalid   VerifyReason = "signature_invalid"
	ReasonFingerprintMismatch VerifyReason = "fingerprint_mismatch"
	ReasonPayloadMismatch    VerifyReason = "payload_mismatch"
	ReasonWatermarkTampered  VerifyReason = "watermark_tampered"
	ReasonTimeRewind         VerifyReason = "time_rewind"
	ReasonNotYetValid        VerifyReason = "not_yet_valid"
	ReasonExpired            VerifyReason = "expired"
	ReasonOfflineTooLong     VerifyReason = "offline_too_long"
	ReasonHardwareUnavailable VerifyReason = "hardware_unavailable"
)

// VerifyResult is what Verify() returns. Reason is always set; Payload
// and DaysLeft are only populated on success (or are best-effort).
type VerifyResult struct {
	Valid     bool         `json:"valid"`
	Reason    VerifyReason `json:"reason"`
	NotAfter  *time.Time   `json:"notAfter,omitempty"`
	DaysLeft  *int         `json:"daysLeft,omitempty"`
	LicenseID string       `json:"licenseId,omitempty"`
	Features  []string     `json:"features,omitempty"`
}
