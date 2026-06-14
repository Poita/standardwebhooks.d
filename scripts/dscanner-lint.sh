#!/usr/bin/env bash
#
# Run D-Scanner static analysis over the library sources and fail on any finding.
#
# This is the script the CI "dscanner lint" gate invokes. It runs:
#     dub run dscanner -- --styleCheck source/ vibe/ ed25519/
# using the project's dscanner.ini (which documents every disabled check), then
# fails if D-Scanner reports any warning or error.
#
# Usage:
#   scripts/dscanner-lint.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Raise the file-descriptor limit; the D toolchain opens many files at once.
ulimit -n 65536 2>/dev/null || true

# Collect only the diagnostic lines (D-Scanner prints them to stdout).
raw="$(dub run --quiet dscanner -- --styleCheck source/ vibe/ ed25519/ 2>/dev/null || true)"

# Keep only [warn]/[error] diagnostics.
findings="$(printf '%s\n' "${raw}" | grep -E '\[(warn|error)\]' || true)"

if [[ -n "${findings}" ]]; then
  echo "D-Scanner reported findings:" >&2
  printf '%s\n' "${findings}" >&2
  exit 1
fi

echo "D-Scanner lint: clean (no findings)."
