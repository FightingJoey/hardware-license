package license

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// TimeRewindTolerance is how far the system clock may move backwards
// from LastSeenAt before we count it as a rewind event. A small skew
// is normal (NTP corrections, container start-up jitter on a battery-
// less device); a large one is suspicious.
const TimeRewindTolerance = 5 * time.Minute

// MaxTimeRewinds is the number of accumulated rewind events that will
// cause Verify() to fail with ReasonTimeRewind. The counter never
// resets, so persistent clock tampering eventually bricks the license
// on this device.
const MaxTimeRewinds = 3

// LoadWatermark reads and authenticates the watermark file. If the
// file does not exist, returns (nil, nil).
//
// The caller MUST verify wm.LicenseID == license.ID after loading;
// pasting another machine's watermark for the same hardware would
// otherwise pass MAC verification (because both machines derive the
// same HMAC key from their identical hardware fingerprint... which is
// impossible to actually achieve, but defense in depth).
func LoadWatermark(path string, key []byte) (*Watermark, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read watermark: %w", err)
	}
	var wm Watermark
	if err := unmarshalStrict(data, &wm); err != nil {
		return nil, fmt.Errorf("parse watermark: %w", err)
	}
	if err := VerifyHMAC(key, &wm); err != nil {
		return nil, fmt.Errorf("watermark mac: %w", err)
	}
	return &wm, nil
}

// SaveWatermark recomputes the HMAC and writes the watermark atomically.
func SaveWatermark(path string, key []byte, wm *Watermark) error {
	mac, err := ComputeHMAC(key, wm)
	if err != nil {
		return err
	}
	wm.MAC = mac
	return WriteJSONFileAtomic(path, wm, 0o600)
}

// AdvanceWatermark applies the monotonic-clock policy described in the
// design doc. It returns the new effective "now" the caller should use
// for expiry checks, and the updated watermark (already MAC'd).
//
//   - Missing watermark → initialise with firstSeen = max(now, issuedAt).
//   - now >= lastSeen           → just bump lastSeen forward.
//   - now <  lastSeen - 5min    → rewind event, keep lastSeen as the
//     effective clock; if too many rewinds accumulate the caller will
//     reject in Verify().
//   - now within tolerance      → ignore the dip, keep lastSeen.
func AdvanceWatermark(prev *Watermark, lic *License, now time.Time) (*Watermark, time.Time, bool) {
	rewind := false
	if prev == nil {
		fs := now
		if lic.IssuedAt.After(fs) {
			fs = lic.IssuedAt
		}
		wm := &Watermark{
			LicenseID:   lic.ID,
			FirstSeenAt: fs,
			LastSeenAt:  fs,
			VerifyCount: 1,
		}
		return wm, fs, false
	}
	wm := *prev
	wm.VerifyCount++

	effective := wm.LastSeenAt
	switch {
	case now.After(wm.LastSeenAt):
		wm.LastSeenAt = now
		effective = now
	case wm.LastSeenAt.Sub(now) > TimeRewindTolerance:
		wm.TimeRewindCount++
		rewind = true
	}
	return &wm, effective, rewind
}

// SameLicense returns true iff this watermark belongs to the given
// license. Used to detect "swap the license file but keep the
// watermark" attacks.
func (w *Watermark) SameLicense(lic *License) bool {
	return w != nil && w.LicenseID == lic.ID
}

// MustValidate centralises the rules for a non-nil, structurally sane
// watermark. It's a sanity check, not a security control on its own.
func (w *Watermark) MustValidate() error {
	if w == nil {
		return errors.New("nil watermark")
	}
	if w.LicenseID == "" {
		return errors.New("watermark missing licenseId")
	}
	if w.FirstSeenAt.IsZero() || w.LastSeenAt.IsZero() {
		return errors.New("watermark missing timestamps")
	}
	if w.LastSeenAt.Before(w.FirstSeenAt) {
		return errors.New("watermark lastSeenAt < firstSeenAt")
	}
	return nil
}
