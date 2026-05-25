// Command licensedb persists signed license metadata to remote MySQL.
// It uses the Go MySQL driver so mysql_native_password servers work
// even when the local mysql CLI (v9+) dropped that plugin.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type record struct {
	LicenseID           string `json:"licenseId"`
	Licensee            string `json:"licensee"`
	IssuedAt            string `json:"issuedAt"`
	NotBefore           string `json:"notBefore"`
	NotAfter            string `json:"notAfter"` // empty for permanent licenses
	Expires             *bool  `json:"expires"`  // optional; absent ⇒ inferred from NotAfter presence
	HardwareFingerprint string `json:"hardwareFingerprint"`
	Features            string `json:"features"`
	MaxOfflineDays      int    `json:"maxOfflineDays"`
	Note                string `json:"note"`
	HardwareRemark      string `json:"hardwareRemark"`
	LicenseFilePath     string `json:"licenseFilePath"`
	LicenseJSON         string `json:"licenseJson"`
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "store" {
		usage()
		os.Exit(2)
	}

	var rec record
	if err := json.NewDecoder(os.Stdin).Decode(&rec); err != nil {
		fail("decode input: %v", err)
	}
	if rec.LicenseID == "" {
		fail("licenseId is required")
	}

	host := env("DB_HOST", "10.191.147.1")
	port := env("DB_PORT", "3306")
	user := env("DB_USER", "root")
	pass := os.Getenv("DB_PASS")
	dbName := env("DB_NAME", "hardware_license")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?parseTime=true&charset=utf8mb4&loc=UTC&timeout=10s",
		user, pass, host, port)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fail("open db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fail("connect db: %v", err)
	}

	if _, err := db.Exec(fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		dbName,
	)); err != nil {
		fail("create database: %v", err)
	}

	if _, err := db.Exec("USE `" + dbName + "`"); err != nil {
		fail("use database: %v", err)
	}

	if err := ensureTable(db); err != nil {
		fail("ensure table: %v", err)
	}

	issuedAt, err := parseTime(rec.IssuedAt)
	if err != nil {
		fail("issuedAt: %v", err)
	}
	notBefore, err := parseTime(rec.NotBefore)
	if err != nil {
		fail("notBefore: %v", err)
	}

	// Permanent licenses arrive with an empty NotAfter (or Go zero time
	// "0001-01-01T00:00:00Z" when re-serialised from the License). Both
	// cases map to SQL NULL.
	var notAfter sql.NullTime
	if rec.NotAfter != "" && rec.NotAfter != "0001-01-01T00:00:00Z" {
		t, perr := parseTime(rec.NotAfter)
		if perr != nil {
			fail("notAfter: %v", perr)
		}
		notAfter = sql.NullTime{Time: t, Valid: true}
	}
	// If the caller did not pass `expires`, infer it from NotAfter
	// presence so existing wrapper scripts keep working.
	expires := notAfter.Valid
	if rec.Expires != nil {
		expires = *rec.Expires
	}

	_, err = db.Exec(`
INSERT INTO licenses (
  license_id, licensee, issued_at, not_before, not_after, expires,
  hardware_fingerprint, features, max_offline_days, note,
  hardware_remark, license_file_path, license_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  licensee = VALUES(licensee),
  issued_at = VALUES(issued_at),
  not_before = VALUES(not_before),
  not_after = VALUES(not_after),
  expires = VALUES(expires),
  hardware_fingerprint = VALUES(hardware_fingerprint),
  features = VALUES(features),
  max_offline_days = VALUES(max_offline_days),
  note = VALUES(note),
  hardware_remark = VALUES(hardware_remark),
  license_file_path = VALUES(license_file_path),
  license_json = VALUES(license_json)`,
		rec.LicenseID,
		rec.Licensee,
		issuedAt,
		notBefore,
		notAfter,
		expires,
		rec.HardwareFingerprint,
		rec.Features,
		rec.MaxOfflineDays,
		nullIfEmpty(rec.Note),
		rec.HardwareRemark,
		nullIfEmpty(rec.LicenseFilePath),
		rec.LicenseJSON,
	)
	if err != nil {
		fail("insert license: %v", err)
	}

	fmt.Fprintf(os.Stderr, "license %s saved to %s@%s:%s/%s\n",
		rec.LicenseID, user, host, port, dbName)
}

func ensureTable(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS licenses (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  license_id           VARCHAR(64)     NOT NULL,
  licensee             VARCHAR(255)    NOT NULL,
  issued_at            DATETIME(3)     NOT NULL,
  not_before           DATETIME(3)     NOT NULL,
  not_after            DATETIME(3)     NULL,
  expires              TINYINT(1)      NOT NULL DEFAULT 1,
  hardware_fingerprint CHAR(64)        NOT NULL,
  features             JSON            NULL,
  max_offline_days     INT             NOT NULL DEFAULT 0,
  note                 TEXT            NULL,
  hardware_remark      LONGTEXT        NOT NULL COMMENT 'hardware.json snapshot',
  license_file_path    VARCHAR(512)    NULL,
  license_json         LONGTEXT        NOT NULL,
  created_at           DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_license_id (license_id),
  KEY idx_licensee (licensee),
  KEY idx_not_after (not_after),
  KEY idx_hardware_fingerprint (hardware_fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
		return err
	}
	// Lazy migration for tables that pre-date the v4 permanent-license
	// support: `not_after` was NOT NULL, `expires` did not exist.
	migrations := []string{
		"ALTER TABLE licenses MODIFY COLUMN not_after DATETIME(3) NULL",
		"ALTER TABLE licenses ADD COLUMN expires TINYINT(1) NOT NULL DEFAULT 1 AFTER not_after",
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			// Idempotent: ignore "column already exists" / "no change"
			// style errors so the migration is safe to re-run.
			if !isHarmlessAlterErr(err) {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
	}
	return nil
}

// MySQL surfaces "duplicate column" and "no change" through specific
// error numbers we can recognise without importing the driver types.
func isHarmlessAlterErr(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	for _, needle := range []string{
		"Duplicate column name",
		"check that column/key exists",
		"Error 1060",
		"Error 1054",
	} {
		if contains(msg, needle) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time value")
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func usage() {
	io.WriteString(os.Stderr, `licensedb — persist signed license metadata to MySQL

Usage:
  licensedb store < record.json

Environment:
  DB_HOST (default: 10.191.147.1)
  DB_PORT (default: 3306)
  DB_USER (default: root)
  DB_PASS
  DB_NAME (default: hardware_license)
`)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "licensedb: "+format+"\n", args...)
	os.Exit(1)
}
