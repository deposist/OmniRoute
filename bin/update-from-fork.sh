#!/usr/bin/env bash
# bin/update-from-fork.sh — in-place update of a globally installed OmniRoute
# (npm install -g) from THIS fork's sources, preserving fork-local features.
#
# Why this exists: `omniroute update --apply` and `npm i -g omniroute@latest`
# both pull the UPSTREAM package from the npm registry, which silently discards
# fork-local work (e.g. the external image-provider plugin ABI). This script
# instead builds the fork checkout and installs that build globally, so the
# running binary always matches the fork.
#
# Data safety: the install itself never rewrites the SQLite store under
# $DATA_DIR, but a consistent snapshot is taken first (bin/snapshot-data.sh) so a
# bad build can be rolled back. Snapshots are interchangeable with the ones the
# server writes on migrations, so bin/restore-data.sh can consume them.
set -euo pipefail
SCRIPT_NAME="update-from-fork"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ops-common.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: bin/update-from-fork.sh [options]

Builds this fork checkout and installs it as the global `omniroute` binary.

Options:
  --ref <git-ref>     Ref to update to (default: the current branch's upstream,
                      else the current branch). Example: release/v3.8.49
  --no-fetch          Skip `git fetch`; build the working tree as-is.
  --skip-snapshot     Do not snapshot $DATA_DIR before installing.
  --skip-restart      Install only; do not stop/start the server.
  --data-dir <path>   Override the data dir (default ~/.omniroute).
  --rollback          Rebuild and reinstall the commit recorded by the last run.
  -y, --yes           Do not prompt for confirmation.
  -h, --help          Show this help.

Env: DATA_DIR (default ~/.omniroute), PORT (passed to `omniroute restart`).

Notes:
  * Run as the user that owns the global npm prefix and $DATA_DIR.
  * Node must satisfy package.json engines (>=22.22.2 <23 || >=24 <27).
  * Do NOT use `omniroute update --apply` on a fork: it installs upstream from
    npm and drops fork-local features.
EOF
}

REF=""
DO_FETCH=1
DO_SNAPSHOT=1
DO_RESTART=1
ASSUME_YES=0
DO_ROLLBACK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --no-fetch) DO_FETCH=0; shift ;;
    --skip-snapshot) DO_SNAPSHOT=0; shift ;;
    --skip-restart) DO_RESTART=0; shift ;;
    --data-dir) ops_set_data_dir "${2:?--data-dir needs a value}"; shift 2 ;;
    --rollback) DO_ROLLBACK=1; shift ;;
    -y | --yes) ASSUME_YES=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) ops_die "unknown argument: $1 (see --help)" ;;
  esac
done

STATE_FILE="${OMNIROUTE_DATA_DIR}/last-fork-update"

ops_require_cmd git
ops_require_cmd npm
ops_require_cmd node

# engines is authoritative: a mismatched Node major produces a build whose native
# deps are compiled against the wrong ABI, which only fails later at boot.
assert_node_supported() {
  local major
  major="$(node -p 'process.versions.node.split(".")[0]')"
  case "$major" in
    22 | 24 | 25 | 26) ;;
    *) ops_die "Node $major is outside package.json engines (>=22.22.2 <23 || >=24 <27). Switch Node (e.g. nvm use 24) and retry." ;;
  esac
}

resolve_target_ref() {
  if [ -n "$REF" ]; then
    printf '%s' "$REF"
    return
  fi
  local upstream
  if upstream="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)"; then
    printf '%s' "$upstream"
  else
    git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD
  fi
}

global_version() {
  # npm ls exits non-zero when the package is absent, so the status is ignored and
  # the parsed value is normalized to a single line ("none" when not installed).
  local out
  out="$(npm ls -g omniroute --depth=0 --json 2>/dev/null | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      try {
        const j = JSON.parse(s);
        console.log((j.dependencies && j.dependencies.omniroute && j.dependencies.omniroute.version) || "none");
      } catch {
        console.log("none");
      }
    });
  ' 2>/dev/null | head -1)"
  printf '%s' "${out:-none}"
}

# Build before the global install: the build is the slow, failure-prone step, and
# aborting there leaves the currently installed binary untouched.
build_and_install() {
  ops_log "installing dependencies (npm ci)"
  (cd "$REPO_ROOT" && npm ci)

  ops_log "building release artifacts (npm run build:release)"
  (cd "$REPO_ROOT" && npm run build:release)

  ops_log "installing build globally (npm install -g .)"
  (cd "$REPO_ROOT" && npm install -g .)
}

restart_server() {
  if [ "$DO_RESTART" -ne 1 ]; then
    ops_log "skipping restart (--skip-restart)"
    return 0
  fi
  ops_log "restarting server"
  if ! omniroute restart ${PORT:+--port "$PORT"}; then
    ops_log "WARNING: 'omniroute restart' failed; start it manually with 'omniroute serve'"
    return 1
  fi
}

verify() {
  ops_log "installed binary version: $(omniroute --version 2>/dev/null || printf 'unknown')"
  ops_log "plugin registry:"
  omniroute plugin list 2>&1 | head -20 || ops_log "  (could not list plugins; check 'omniroute status')"
}

if [ "$DO_ROLLBACK" -eq 1 ]; then
  [ -f "$STATE_FILE" ] || ops_die "no rollback state at $STATE_FILE (nothing recorded yet)"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  : "${PREV_SHA:?state file is missing PREV_SHA}"
  ops_log "rolling back to $PREV_SHA (previous global version: ${PREV_VERSION:-unknown})"
  [ "$ASSUME_YES" -eq 1 ] || ops_confirm "Rebuild and reinstall commit $PREV_SHA?"
  assert_node_supported
  git -C "$REPO_ROOT" checkout --quiet --detach "$PREV_SHA"
  omniroute stop >/dev/null 2>&1 || true
  build_and_install
  restart_server || true
  verify
  ops_log "rollback complete. Data was not modified by the install itself;"
  ops_log "restore ${SNAPSHOT_ID:-<snapshot-id>} with bin/restore-data.sh only if the DB was migrated."
  exit 0
fi

assert_node_supported

TARGET_REF="$(resolve_target_ref)"
CURRENT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
CURRENT_VERSION="$(global_version)"

ops_log "repo:           $REPO_ROOT"
ops_log "data dir:       $OMNIROUTE_DATA_DIR"
ops_log "target ref:     $TARGET_REF"
ops_log "current commit: $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
ops_log "global version: $CURRENT_VERSION"

# Uncommitted fork-local edits would either be baked into the build silently or
# be destroyed by the checkout below, so refuse to guess.
if [ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]; then
  ops_die "working tree is dirty. Commit or stash changes first (git -C $REPO_ROOT status)."
fi

if [ "$DO_FETCH" -eq 1 ]; then
  ops_log "fetching refs"
  git -C "$REPO_ROOT" fetch --prune --tags origin
fi

git -C "$REPO_ROOT" rev-parse --verify --quiet "${TARGET_REF}^{commit}" >/dev/null ||
  ops_die "ref not found: $TARGET_REF"
TARGET_SHA="$(git -C "$REPO_ROOT" rev-parse "${TARGET_REF}^{commit}")"

if [ "$TARGET_SHA" = "$CURRENT_SHA" ]; then
  ops_log "already at $TARGET_REF; rebuilding anyway"
else
  ops_log "updating $(git -C "$REPO_ROOT" rev-parse --short "$CURRENT_SHA") -> $(git -C "$REPO_ROOT" rev-parse --short "$TARGET_SHA")"
  git -C "$REPO_ROOT" --no-pager log --oneline "$CURRENT_SHA..$TARGET_SHA" 2>/dev/null | head -15 >&2 || true
fi

[ "$ASSUME_YES" -eq 1 ] || ops_confirm "Build $TARGET_REF and replace the global omniroute install?"

SNAPSHOT_ID=""
if [ "$DO_SNAPSHOT" -eq 1 ]; then
  ops_log "snapshotting data dir"
  SNAPSHOT_ID="$("$REPO_ROOT/bin/snapshot-data.sh" --label pre-update --data-dir "$OMNIROUTE_DATA_DIR")"
  ops_log "snapshot id: $SNAPSHOT_ID"
else
  ops_log "skipping snapshot (--skip-snapshot)"
fi

# Recorded before the checkout so --rollback targets the exact commit that was
# known-good, regardless of where the ref points later.
mkdir -p "$OMNIROUTE_DATA_DIR"
{
  printf 'PREV_SHA=%s\n' "$CURRENT_SHA"
  printf 'PREV_VERSION=%s\n' "$CURRENT_VERSION"
  printf 'UPDATED_TO=%s\n' "$TARGET_SHA"
  printf 'UPDATED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -n "$SNAPSHOT_ID" ] && printf 'SNAPSHOT_ID=%s\n' "$SNAPSHOT_ID"
} >"$STATE_FILE"

ops_log "stopping server"
omniroute stop >/dev/null 2>&1 || ops_log "  (server was not running)"

git -C "$REPO_ROOT" checkout --quiet --detach "$TARGET_SHA"

build_and_install
restart_server || true
verify

ops_log "update complete: $(git -C "$REPO_ROOT" rev-parse --short "$TARGET_SHA")"
ops_log "rollback with: bin/update-from-fork.sh --rollback"
