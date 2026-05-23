package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"
)

// VerifyOptions wires the verifier to its on-disk inputs.
type VerifyOptions struct {
	LicensePath   string
	PublicKey     ed25519.PublicKey
	WatermarkPath string
	Fingerprint   FingerprintConfig

	// Now lets tests inject the wall clock. Production callers leave
	// this zero so time.Now().UTC() is used.
	Now time.Time

	// Logger is invoked once with a structured event describing the
	// verification outcome. May be nil.
	Logger func(event VerifyEvent)
}

// VerifyEvent is what the optional Logger receives. We deliberately
// keep the details out of VerifyResult so the public Status API can
// stay opaque while operators still get useful diagnostics on the box.
type VerifyEvent struct {
	Reason      VerifyReason
	Err         error
	LicenseID   string
	Fingerprint string
	Now         time.Time
	Effective   time.Time
}

// Verify is the single source of truth. The Next.js side calls into
// either this function (when embedding Go via cgo) or its TypeScript
// twin in verifier-node.
func Verify(opts VerifyOptions) VerifyResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	log := opts.Logger
	emit := func(reason VerifyReason, err error, licID, fp string, eff time.Time) VerifyResult {
		if log != nil {
			log(VerifyEvent{Reason: reason, Err: err, LicenseID: licID, Fingerprint: fp, Now: now, Effective: eff})
		}
		res := VerifyResult{Valid: reason == ReasonOK, Reason: reason}
		if reason == ReasonOK {
			res.LicenseID = licID
		}
		return res
	}

	// 1. Read and structurally parse the license.
	var lic License
	if err := ReadJSONFileStrict(opts.LicensePath, &lic); err != nil {
		return emit(ReasonMalformed, err, "", "", time.Time{})
	}
	if lic.Version != FormatVersion {
		return emit(ReasonUnsupportedVersion,
			fmt.Errorf("got version %d, want %d", lic.Version, FormatVersion), lic.ID, "", time.Time{})
	}
	if lic.ID == "" || lic.HardwareFingerprint == "" || lic.NotAfter.IsZero() || lic.IssuedAt.IsZero() {
		return emit(ReasonMalformed, errors.New("missing required field"), lic.ID, "", time.Time{})
	}

	// 2. Signature check first — it's the cheapest hard gate.
	if err := VerifySignature(opts.PublicKey, &lic); err != nil {
		return emit(ReasonSignatureInvalid, err, lic.ID, "", time.Time{})
	}

	// 3. Hardware fingerprint.
	info, err := CollectHardwareInfo(opts.Fingerprint)
	if err != nil {
		return emit(ReasonHardwareUnavailable, err, lic.ID, "", time.Time{})
	}
	if info.Fingerprint != lic.HardwareFingerprint {
		err := fmt.Errorf("device fp %s != license fp %s", info.Fingerprint, lic.HardwareFingerprint)
		if os.Geteuid() != 0 {
			if locked := RootLockedDMISourceKeys(opts.Fingerprint); len(locked) > 0 {
				err = fmt.Errorf("%w; unreadable root-only DMI fields %v (retry with sudo)", err, locked)
			}
		}
		return emit(ReasonFingerprintMismatch, err, lic.ID, info.Fingerprint, time.Time{})
	}

	// 4. Derive keys.
	fpBytes, err := FingerprintBytes(lic.HardwareFingerprint)
	if err != nil {
		return emit(ReasonMalformed, err, lic.ID, info.Fingerprint, time.Time{})
	}
	aesKey, err := DeriveKey(fpBytes, lic.ID, HKDFInfoPayloadKey)
	if err != nil {
		return emit(ReasonMalformed, err, lic.ID, info.Fingerprint, time.Time{})
	}
	defer zero(aesKey)
	hmacKey, err := DeriveKey(fpBytes, lic.ID, HKDFInfoWatermarkKey)
	if err != nil {
		return emit(ReasonMalformed, err, lic.ID, info.Fingerprint, time.Time{})
	}
	defer zero(hmacKey)

	// 5. Decrypt + cross-bind payload to header.
	payload, err := DecryptPayload(aesKey, lic.EncryptedPayload)
	if err != nil {
		return emit(ReasonMalformed, err, lic.ID, info.Fingerprint, time.Time{})
	}
	if payload.ID != lic.ID {
		return emit(ReasonPayloadMismatch,
			fmt.Errorf("payload.id %s != license.id %s", payload.ID, lic.ID),
			lic.ID, info.Fingerprint, time.Time{})
	}
	if !payload.NotAfter.Equal(lic.NotAfter) {
		return emit(ReasonPayloadMismatch,
			fmt.Errorf("payload.notAfter != license.notAfter"),
			lic.ID, info.Fingerprint, time.Time{})
	}

	// 6. Watermark.
	wm, err := LoadWatermark(opts.WatermarkPath, hmacKey)
	if err != nil {
		return emit(ReasonWatermarkTampered, err, lic.ID, info.Fingerprint, time.Time{})
	}
	if wm != nil {
		if !wm.SameLicense(&lic) {
			return emit(ReasonWatermarkTampered,
				fmt.Errorf("watermark belongs to license %s, current is %s", wm.LicenseID, lic.ID),
				lic.ID, info.Fingerprint, time.Time{})
		}
		if err := wm.MustValidate(); err != nil {
			return emit(ReasonWatermarkTampered, err, lic.ID, info.Fingerprint, time.Time{})
		}
	}

	next, effective, _ := AdvanceWatermark(wm, &lic, now)

	if next.TimeRewindCount > MaxTimeRewinds {
		// We still persist the bumped counter so an attacker can't make
		// progress by repeatedly killing the process before the file
		// gets re-written.
		_ = SaveWatermark(opts.WatermarkPath, hmacKey, next)
		return emit(ReasonTimeRewind,
			fmt.Errorf("time_rewind_count=%d > %d", next.TimeRewindCount, MaxTimeRewinds),
			lic.ID, info.Fingerprint, effective)
	}

	// 7. Time gates against the *effective* clock.
	if effective.Before(lic.NotBefore) {
		_ = SaveWatermark(opts.WatermarkPath, hmacKey, next)
		return emit(ReasonNotYetValid, nil, lic.ID, info.Fingerprint, effective)
	}
	if effective.After(lic.NotAfter) {
		_ = SaveWatermark(opts.WatermarkPath, hmacKey, next)
		return emit(ReasonExpired, nil, lic.ID, info.Fingerprint, effective)
	}

	// 8. Offline-duration cap (compares against the *real* wall clock,
	//    not the effective clock — we only want to know "how long since
	//    we last saw a fresh license"; that requires real-time deltas).
	if payload.MaxOfflineDays > 0 && wm != nil {
		gap := now.Sub(wm.LastSeenAt)
		if gap.Hours()/24 > float64(payload.MaxOfflineDays) {
			_ = SaveWatermark(opts.WatermarkPath, hmacKey, next)
			return emit(ReasonOfflineTooLong,
				fmt.Errorf("gap=%s > %dd", gap, payload.MaxOfflineDays),
				lic.ID, info.Fingerprint, effective)
		}
	}

	// 9. Success — persist updated watermark, build the public result.
	if err := SaveWatermark(opts.WatermarkPath, hmacKey, next); err != nil {
		return emit(ReasonMalformed, fmt.Errorf("save watermark: %w", err),
			lic.ID, info.Fingerprint, effective)
	}

	days := int(lic.NotAfter.Sub(effective).Hours() / 24)
	notAfter := lic.NotAfter
	if log != nil {
		log(VerifyEvent{Reason: ReasonOK, LicenseID: lic.ID, Fingerprint: info.Fingerprint, Now: now, Effective: effective})
	}
	return VerifyResult{
		Valid:     true,
		Reason:    ReasonOK,
		NotAfter:  &notAfter,
		DaysLeft:  &days,
		LicenseID: lic.ID,
		Features:  payload.Features,
	}
}
