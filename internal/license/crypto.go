package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// LoadEd25519Private parses an unencrypted PKCS#8 PEM private key file
// and returns the underlying ed25519.PrivateKey. We deliberately do not
// support encrypted keys; the issuer must keep this file on a trusted
// host (HSM/SE in production).
func LoadEd25519Private(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519 (got %T)", key)
	}
	return ed, nil
}

// LoadEd25519Public parses a PKIX PEM public key file.
func LoadEd25519Public(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519 (got %T)", key)
	}
	return ed, nil
}

// GenerateEd25519Keypair creates a new key pair and writes both halves
// to PEM files (PKCS#8 / PKIX). The private file is created with 0600.
func GenerateEd25519Keypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519 keygen: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public: %w", err)
	}
	if err := writeFileSecure(privPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}), 0o600); err != nil {
		return err
	}
	if err := writeFileSecure(pubPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}), 0o644); err != nil {
		return err
	}
	return nil
}

func writeFileSecure(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// FingerprintBytes returns the raw 32-byte digest behind the hex
// HardwareFingerprint. This is the IKM (input keying material) for
// HKDF; never expose it outside the verifier.
func FingerprintBytes(hexFP string) ([]byte, error) {
	b, err := hex.DecodeString(hexFP)
	if err != nil {
		return nil, fmt.Errorf("decode fingerprint hex: %w", err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("fingerprint must be %d bytes, got %d", sha256.Size, len(b))
	}
	return b, nil
}

// DeriveKey runs HKDF-SHA256 over the hardware fingerprint bytes with
// the license ID as salt and a constant info string as domain
// separation. Output is always 32 bytes.
func DeriveKey(fpBytes []byte, licenseID, info string) ([]byte, error) {
	if len(fpBytes) == 0 {
		return nil, errors.New("derive key: empty fingerprint")
	}
	r := hkdf.New(sha256.New, fpBytes, []byte(licenseID), []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	return out, nil
}

// EncryptPayload seals the canonical-JSON encoding of a Payload with
// AES-256-GCM. Caller must already have derived `key` via DeriveKey
// with HKDFInfoPayloadKey.
func EncryptPayload(key []byte, payload *Payload) (EncryptedPayload, error) {
	plaintext, err := CanonicalJSONOf(payload)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("canonicalize payload: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return EncryptedPayload{
		Alg:        "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// DecryptPayload reverses EncryptPayload. A failure here is
// indistinguishable from tampering thanks to GCM's auth tag.
func DecryptPayload(key []byte, enc EncryptedPayload) (*Payload, error) {
	if enc.Alg != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported alg %q", enc.Alg)
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	var p Payload
	if err := unmarshalStrict(pt, &p); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return &p, nil
}

// SignLicense fills in license.Signature. It mutates the input.
func SignLicense(priv ed25519.PrivateKey, lic *License) error {
	lic.Signature = ""
	msg, err := CanonicalJSONOf(lic)
	if err != nil {
		return fmt.Errorf("canonicalize license: %w", err)
	}
	sig := ed25519.Sign(priv, msg)
	lic.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifySignature returns nil if the signature is valid.
func VerifySignature(pub ed25519.PublicKey, lic *License) error {
	sig, err := base64.StdEncoding.DecodeString(lic.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	clone := *lic
	clone.Signature = ""
	msg, err := CanonicalJSONOf(&clone)
	if err != nil {
		return fmt.Errorf("canonicalize license: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

// ComputeHMAC over the watermark, excluding its own MAC field.
func ComputeHMAC(key []byte, wm *Watermark) (string, error) {
	clone := *wm
	clone.MAC = ""
	msg, err := CanonicalJSONOf(&clone)
	if err != nil {
		return "", fmt.Errorf("canonicalize watermark: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC returns nil if the MAC matches.
func VerifyHMAC(key []byte, wm *Watermark) error {
	want, err := ComputeHMAC(key, wm)
	if err != nil {
		return err
	}
	got, err := base64.StdEncoding.DecodeString(wm.MAC)
	if err != nil {
		return fmt.Errorf("decode mac: %w", err)
	}
	wantBytes, _ := base64.StdEncoding.DecodeString(want)
	if !hmac.Equal(wantBytes, got) {
		return errors.New("watermark HMAC mismatch")
	}
	return nil
}
