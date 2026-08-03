#!/usr/bin/env bash
set -euo pipefail

readonly UPSTREAM_URL="https://github.com/bitcoin-core/secp256k1"
readonly LOG_PREFIX="[vendor-secp256k1]"

usage() {
  printf 'Usage: %s vMAJOR.MINOR.PATCH [--allow-unverified]\n' "${0##*/}" >&2
}

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$*"
}

warn() {
  printf '%s WARNING: %s\n' "$LOG_PREFIX" "$*" >&2
}

die() {
  printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2
  exit 1
}

if (( $# < 1 || $# > 2 )); then
  usage
  exit 2
fi

readonly VERSION="$1"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  usage
  exit 2
fi

ALLOW_UNVERIFIED=0
if (( $# == 2 )); then
  if [[ "$2" != "--allow-unverified" ]]; then
    usage
    exit 2
  fi
  ALLOW_UNVERIFIED=1
fi
readonly ALLOW_UNVERIFIED

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly ROOT

log "Starting vendoring for $VERSION"
log "Checking maintainer tools"

missing_tools=()
required_tools=(git make autoreconf awk tar sed diff mktemp cp mv rm mkdir wc dirname)
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done

SHA_TOOL=""
if command -v sha256sum >/dev/null 2>&1; then
  SHA_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_TOOL="shasum"
else
  missing_tools+=("sha256sum or shasum")
fi

if (( ! ALLOW_UNVERIFIED )) && ! command -v gpg >/dev/null 2>&1; then
  missing_tools+=("gpg")
fi

if (( ${#missing_tools[@]} > 0 )); then
  printf '%s ERROR: missing required tools:' "$LOG_PREFIX" >&2
  printf ' %s' "${missing_tools[@]}" >&2
  printf '\n' >&2
  exit 1
fi
readonly SHA_TOOL

TMP="$(mktemp -d)"
readonly TMP

cleanup() {
  rm -rf "$TMP"
}

on_error() {
  local status="$1"
  local line="$2"
  trap - ERR
  printf '%s ERROR: command failed at line %s (exit %s)\n' "$LOG_PREFIX" "$line" "$status" >&2
  exit "$status"
}

trap cleanup EXIT
trap 'on_error $? $LINENO' ERR

sha256_file() {
  local file="$1"

  if [[ "$SHA_TOOL" == "sha256sum" ]]; then
    sha256sum "$file" | awk '{ print $1 }'
  else
    shasum -a 256 "$file" | awk '{ print $1 }'
  fi
}

pin_count() {
  local pin="$1"
  awk -v pin="$pin" '$0 ~ "^" pin " := " { count++ } END { print count + 0 }' "$ROOT/Makefile"
}

log "Cloning signed upstream tag $VERSION"
git clone --depth 1 --branch "$VERSION" "$UPSTREAM_URL" "$TMP/src"

TAG_VERIFICATION=""
if command -v gpg >/dev/null 2>&1; then
  log "Verifying GPG signature on tag $VERSION"
  if git -C "$TMP/src" tag -v "$VERSION"; then
    TAG_VERIFICATION="verified"
  elif (( ALLOW_UNVERIFIED )); then
    TAG_VERIFICATION="UNVERIFIED (--allow-unverified; tag verification failed)"
    warn "Tag verification failed; continuing only because --allow-unverified was supplied"
  else
    die "tag verification failed; import the upstream release signing key and retry, or explicitly use --allow-unverified"
  fi
else
  TAG_VERIFICATION="UNVERIFIED (--allow-unverified; gpg unavailable)"
  warn "gpg is unavailable; continuing only because --allow-unverified was supplied"
fi
readonly TAG_VERIFICATION

COMMIT="$(git -C "$TMP/src" rev-parse 'HEAD^{commit}')"
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  die "peeled tag commit is not a 40-character lowercase hexadecimal object ID: $COMMIT"
fi
readonly COMMIT
log "Recorded peeled tag commit $COMMIT"

log "Generating release build system with autogen.sh"
(
  cd "$TMP/src"
  ./autogen.sh
)

log "Configuring upstream release workspace"
(
  cd "$TMP/src"
  ./configure
)

log "Running upstream make distcheck (this can take several minutes)"
(
  cd "$TMP/src"
  make distcheck
)

shopt -s nullglob
dist_archives=("$TMP/src"/secp256k1-*.tar.gz)
if (( ${#dist_archives[@]} != 1 )); then
  die "expected exactly one dist archive, found ${#dist_archives[@]}"
fi
DIST="${dist_archives[0]}"
readonly DIST

SHA256="$(sha256_file "$DIST")"
if [[ ! "$SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  die "computed SHA256 is not 64 lowercase hexadecimal characters: $SHA256"
fi
readonly SHA256
log "Validated one dist archive with SHA256 $SHA256"

for pin in LIB_VERSION LIB_COMMIT LIB_SHA256; do
  count="$(pin_count "$pin")"
  if [[ "$count" != "1" ]]; then
    die "expected exactly one '$pin := ' assignment in Makefile, found $count"
  fi
done

sed \
  -e "s/^LIB_VERSION := .*/LIB_VERSION := $VERSION/" \
  -e "s/^LIB_COMMIT := .*/LIB_COMMIT := $COMMIT/" \
  -e "s/^LIB_SHA256 := .*/LIB_SHA256 := $SHA256/" \
  "$ROOT/Makefile" > "$TMP/Makefile.new"

if diff "$ROOT/Makefile" "$TMP/Makefile.new" > "$TMP/Makefile.diff"; then
  die "generated pins do not change Makefile"
else
  diff_status=$?
  if (( diff_status != 1 )); then
    die "could not compare current and generated Makefiles (diff exit $diff_status)"
  fi
fi

if ! awk '
  /^[<>] / {
    changed++
    line = substr($0, 3)
    if (line !~ /^LIB_(VERSION|COMMIT|SHA256) := /) {
      invalid = 1
    }
  }
  END {
    if (changed == 0 || invalid) {
      exit 1
    }
  }
' "$TMP/Makefile.diff"; then
  die "generated Makefile changes something other than the three pin assignments"
fi
log "Validated out-of-tree Makefile pin update"

log "Backing up the current Makefile and archive set"
mkdir "$TMP/backup"
cp -p "$ROOT/Makefile" "$TMP/backup/Makefile"

old_archives=("$ROOT"/c_src/secp256k1-v*.tar.gz)
for archive in "${old_archives[@]}"; do
  cp -p "$archive" "$TMP/backup/${archive##*/}"
done

NEW_ARCHIVE="$ROOT/c_src/secp256k1-$VERSION.tar.gz"
STAGED_ARCHIVE="$ROOT/c_src/.secp256k1-$VERSION.tar.gz.new"
readonly NEW_ARCHIVE STAGED_ARCHIVE

rollback() {
  local status="$1"
  local reason="$2"
  local current_archives backup_archives archive

  trap - ERR INT TERM
  set +e
  printf '%s ERROR: %s; rolling back repository files\n' "$LOG_PREFIX" "$reason" >&2

  rm -f "$STAGED_ARCHIVE"
  rm -f "$NEW_ARCHIVE"
  rm -f "$ROOT/Makefile"

  current_archives=("$ROOT"/c_src/secp256k1-v*.tar.gz)
  for archive in "${current_archives[@]}"; do
    rm -f "$archive"
  done

  cp -p "$TMP/backup/Makefile" "$ROOT/Makefile"
  backup_archives=("$TMP"/backup/secp256k1-v*.tar.gz)
  for archive in "${backup_archives[@]}"; do
    cp -p "$archive" "$ROOT/c_src/${archive##*/}"
  done

  printf '%s Rollback complete\n' "$LOG_PREFIX" >&2
  exit "$status"
}

transaction_abort() {
  rollback 1 "$1"
}

trap 'rollback $? "install command failed at line $LINENO"' ERR
trap 'rollback 130 "installation interrupted by INT"' INT
trap 'rollback 143 "installation interrupted by TERM"' TERM

log "Installing archive and Makefile pins transactionally"
cp "$DIST" "$STAGED_ARCHIVE"
mv "$STAGED_ARCHIVE" "$NEW_ARCHIVE"
mv "$TMP/Makefile.new" "$ROOT/Makefile"

log "Removing prior archives"
installed_archives=("$ROOT"/c_src/secp256k1-v*.tar.gz)
for archive in "${installed_archives[@]}"; do
  if [[ "$archive" != "$NEW_ARCHIVE" ]]; then
    rm -f "$archive"
  fi
done

log "Checking post-update repository invariants"
installed_archives=("$ROOT"/c_src/secp256k1-v*.tar.gz)
if (( ${#installed_archives[@]} != 1 )); then
  transaction_abort "expected exactly one installed archive, found ${#installed_archives[@]}"
fi
if [[ "${installed_archives[0]##*/}" != "secp256k1-$VERSION.tar.gz" ]]; then
  transaction_abort "installed archive name does not contain requested version $VERSION"
fi

installed_version="$(awk '/^LIB_VERSION := / { print $3 }' "$ROOT/Makefile")"
installed_commit="$(awk '/^LIB_COMMIT := / { print $3 }' "$ROOT/Makefile")"
installed_sha256="$(awk '/^LIB_SHA256 := / { print $3 }' "$ROOT/Makefile")"
archive_sha256="$(sha256_file "${installed_archives[0]}")"

if [[ "$installed_version" != "$VERSION" ]]; then
  transaction_abort "Makefile version pin does not match $VERSION"
fi
if [[ "$installed_commit" != "$COMMIT" ]]; then
  transaction_abort "Makefile commit pin does not match peeled tag commit $COMMIT"
fi
if [[ "$installed_sha256" != "$SHA256" ]]; then
  transaction_abort "Makefile SHA256 pin does not match generated archive digest $SHA256"
fi
if [[ "$archive_sha256" != "$installed_sha256" ]]; then
  transaction_abort "installed archive digest does not match Makefile SHA256 pin"
fi

trap - ERR INT TERM

log "Removing stale extracted trees after successful invariant checks"
rm -rf "$ROOT/c_src/secp256k1" "$ROOT/c_src/secp256k1.tmp"

archive_size="$(wc -c < "${installed_archives[0]}")"
archive_size="${archive_size//[[:space:]]/}"

log "Completed vendoring for $VERSION"
printf '%s VERSION: %s\n' "$LOG_PREFIX" "$VERSION"
printf '%s COMMIT: %s\n' "$LOG_PREFIX" "$COMMIT"
printf '%s SHA256: %s\n' "$LOG_PREFIX" "$SHA256"
printf '%s TAG VERIFICATION: %s\n' "$LOG_PREFIX" "$TAG_VERIFICATION"
printf '%s TARBALL: %s (%s bytes)\n' "$LOG_PREFIX" "${installed_archives[0]}" "$archive_size"
printf '%s Next: update CHANGELOG.md; run mix clean, mix compile, and mix test; commit the tarball and Makefile.\n' "$LOG_PREFIX"
