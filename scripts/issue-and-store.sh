#!/usr/bin/env bash
# Sign a license with `issuer sign`, then persist metadata to remote MySQL.
#
# Usage (same flags as issuer sign):
#   ./scripts/issue-and-store.sh \
#     -hardware hardware.json \
#     -priv private.pem \
#     -licensee "ACME Corp" \
#     -not-after 2027-05-21 \
#     -features pro,ai-camera \
#     -max-offline-days 90 \
#     -out license.json
#
# Remote MySQL (default 10.191.147.1:3306), override via environment:
#   DB_HOST=10.191.147.1  DB_PORT=3306  DB_USER=root  DB_PASS=secret  DB_NAME=hardware_license
#
# Requires: build/issuer, build/licensedb, jq

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUER="${ISSUER:-$ROOT/build/issuer}"
LICENSEDB="${LICENSEDB:-$ROOT/build/licensedb}"

DB_HOST="${DB_HOST:-10.191.147.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-}"
DB_NAME="${DB_NAME:-hardware_license}"

die() {
  echo "issue-and-store: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

parse_sign_flags() {
  HARDWARE=""
  HARDWARE_OUT="hardware.json"
  LOCAL=false
  OUT="license.json"
  local argc=$#
  local -a argv=("$@")
  local i=0
  while (( i < argc )); do
    case "${argv[i]}" in
      -local)
        LOCAL=true
        ((i += 1))
        ;;
      -hardware)
        HARDWARE="${argv[i+1]:-}"
        ((i += 2))
        ;;
      -hardware-out)
        HARDWARE_OUT="${argv[i+1]:-}"
        ((i += 2))
        ;;
      -out)
        OUT="${argv[i+1]:-}"
        ((i += 2))
        ;;
      *)
        ((i += 1))
        ;;
    esac
  done
  if $LOCAL; then
    HARDWARE="${HARDWARE_OUT}"
  else
    [[ -n "$HARDWARE" ]] || HARDWARE="hardware.json"
  fi
}

usage() {
  cat <<'EOF'
issue-and-store — sign a license and save it to MySQL

Usage:
  ./scripts/issue-and-store.sh [issuer sign flags...]

Required issuer flags (remote signing):
  -hardware PATH     hardware.json from the device
  -priv PATH         Ed25519 private key
  -licensee NAME     customer / licensee name
  -not-after DATE    expiry (YYYY-MM-DD or RFC3339)

On-device signing:
  -local             collect hardware on this machine and sign in place
  -nic / -disk-name / -require-gpu   same as hwinfo (see README)
  -hardware-out PATH snapshot written during -local (default: hardware.json)

Common optional flags:
  -out PATH          output license file (default: license.json)
  -features LIST     comma-separated feature flags
  -max-offline-days N
  -note TEXT
  -force

Database environment variables:
  DB_HOST (default: 10.191.147.1)
  DB_PORT (default: 3306)
  DB_USER (default: root)
  DB_PASS (default: empty)
  DB_NAME (default: hardware_license)
EOF
}

main() {
  if [[ $# -eq 0 ]] || [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_cmd jq
  [[ -x "$ISSUER" ]] || die "issuer not found at $ISSUER (run: make issuer licensedb)"
  [[ -x "$LICENSEDB" ]] || die "licensedb not found at $LICENSEDB (run: make licensedb)"

  parse_sign_flags "$@"

  echo "==> signing license..."
  "$ISSUER" sign "$@"

  [[ -f "$OUT" ]] || die "license file not found after sign: $OUT"
  [[ -f "$HARDWARE" ]] || die "hardware file not found: $HARDWARE"

  local license_id licensee issued_at not_before not_after fingerprint
  license_id=$(jq -r '.id' "$OUT")
  licensee=$(jq -r '.licensee' "$OUT")
  issued_at=$(jq -r '.issuedAt' "$OUT")
  not_before=$(jq -r '.notBefore' "$OUT")
  not_after=$(jq -r '.notAfter' "$OUT")
  fingerprint=$(jq -r '.hardwareFingerprint' "$OUT")

  [[ -n "$license_id" && "$license_id" != "null" ]] || die "invalid license id in $OUT"

  local inspect_json features max_offline note payload_note
  inspect_json=$("$ISSUER" inspect -license "$OUT" -hardware "$HARDWARE")
  features=$(jq -c '.payload.features // []' <<<"$inspect_json")
  max_offline=$(jq -r '.payload.maxOfflineDays // 0' <<<"$inspect_json")
  payload_note=$(jq -r '.payload.note // ""' <<<"$inspect_json")
  note="$payload_note"

  local license_json hardware_remark
  license_json=$(jq -c . "$OUT")
  hardware_remark=$(jq -c . "$HARDWARE")

  local out_abs
  out_abs=$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")

  echo "==> saving license to database ($DB_HOST:$DB_PORT/$DB_NAME)..."
  DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" DB_PASS="$DB_PASS" DB_NAME="$DB_NAME" \
    jq -n \
      --arg licenseId "$license_id" \
      --arg licensee "$licensee" \
      --arg issuedAt "$issued_at" \
      --arg notBefore "$not_before" \
      --arg notAfter "$not_after" \
      --arg hardwareFingerprint "$fingerprint" \
      --argjson features "$features" \
      --argjson maxOfflineDays "$max_offline" \
      --arg note "$note" \
      --arg hardwareRemark "$hardware_remark" \
      --arg licenseFilePath "$out_abs" \
      --arg licenseJson "$license_json" \
      '{
        licenseId: $licenseId,
        licensee: $licensee,
        issuedAt: $issuedAt,
        notBefore: $notBefore,
        notAfter: $notAfter,
        hardwareFingerprint: $hardwareFingerprint,
        features: ($features | tojson),
        maxOfflineDays: $maxOfflineDays,
        note: $note,
        hardwareRemark: $hardwareRemark,
        licenseFilePath: $licenseFilePath,
        licenseJson: $licenseJson
      }' | "$LICENSEDB" store

  echo "done."
  echo "  license file: $out_abs"
  echo "  license id:   $license_id"
  echo "  database:     $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
}

main "$@"
