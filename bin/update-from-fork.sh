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
# Low-memory hosts: the Next build needs ~2.5 GB of heap and is OOM-killed
# silently below that, so a small server cannot build at all. Use --tarball with
# an artifact from .github/workflows/fork-build-tarball.yml to install a prebuilt
# package instead; package.json#files ships dist/, and the only install hook is
# postinstall (native binary fixups), so no Next build happens on the server.
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
  --tarball <path>    Install a prebuilt .tgz instead of building from source.
                      Accepts the GitHub artifact .zip directly (the .tgz is
                      extracted from it). Use this on hosts with <4 GB RAM.
  --from-ci           Download the newest successful Build Fork Tarball artifact
                      from GitHub Actions and install that, no browser or scp.
                      Needs a token with Actions:read in $GH_TOKEN, or in
                      ~/.config/omniroute/gh-token (chmod 600). Artifacts expire
                      after the workflow's retention window.
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
  * --tarball skips git fetch/checkout and the build; the running commit of this
    checkout is irrelevant to what gets installed. Installed tarballs are kept in
    $DATA_DIR/tarballs so --rollback can reinstall the previous one.
  * Node must satisfy package.json engines (>=22.22.2 <23 || >=24 <27).
  * Do NOT use `omniroute update --apply` on a fork: it installs upstream from
    npm and drops fork-local features.
EOF
}

REF=""
TARBALL=""
FROM_CI=0
DO_FETCH=1
DO_SNAPSHOT=1
DO_RESTART=1
ASSUME_YES=0
DO_ROLLBACK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --tarball) TARBALL="${2:?--tarball needs a value}"; shift 2 ;;
    --from-ci) FROM_CI=1; shift ;;
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

# GitHub hands out workflow artifacts as .zip, so accept that shape too instead of
# making the operator unzip by hand. Logs go to stderr (ops_log), keeping stdout
# clean for the resolved path used by command substitution.
# --from-ci: pull the newest successful Build Fork Tarball artifact straight onto
# this host. Deliberately pull-based: deploy-vps.yml already tried the push
# direction (runner -> SSH into the VPS) and is permanently SKIPped because the
# host firewalls :22 away from GitHub runners, so the server has to fetch instead.
#
# Artifact download always needs auth, even on a public repo (GitHub API rule), so
# a token with Actions:read is required. Read it from the environment or a 0600
# file, never from a CLI flag, so it cannot leak into shell history or `ps`.
GH_TOKEN_FILE_DEFAULT="${XDG_CONFIG_HOME:-$HOME/.config}/omniroute/gh-token"
FORK_REPO_DEFAULT="deposist/OmniRoute"
FORK_WORKFLOW_FILE="fork-build-tarball.yml"

# Prints the token or nothing. It must NOT ops_die: this runs inside a command
# substitution, where a die would only kill the subshell and let the caller carry
# on with an empty token -- which surfaced as a confusing Node/API error instead of
# "no token". The caller checks for empty and reports.
ci_token() {
  local file="${OMNIROUTE_GH_TOKEN_FILE:-$GH_TOKEN_FILE_DEFAULT}"
  if [ -n "${GH_TOKEN:-}" ]; then printf '%s' "$GH_TOKEN"; return 0; fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then printf '%s' "$GITHUB_TOKEN"; return 0; fi
  [ -f "$file" ] || return 0
  tr -d '[:space:]' <"$file"
}

fetch_ci_tarball() {
  local repo="${OMNIROUTE_FORK_REPO:-$FORK_REPO_DEFAULT}" token api run_id name url tmp out
  ops_require_cmd curl
  ops_require_cmd node
  token="$(ci_token)"
  [ -n "$token" ] ||
    ops_die "no GitHub token. Put one with Actions:read on ${repo} in \$GH_TOKEN, or in ${OMNIROUTE_GH_TOKEN_FILE:-$GH_TOKEN_FILE_DEFAULT} (chmod 600)."
  api="https://api.github.com/repos/${repo}"

  ops_log "looking up the newest successful ${FORK_WORKFLOW_FILE} run on ${repo}"
  run_id="$(curl -fsSL -H "Authorization: Bearer ${token}" \
    -H "Accept: application/vnd.github+json" \
    "${api}/actions/workflows/${FORK_WORKFLOW_FILE}/runs?status=success&per_page=1" |
    node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const r=JSON.parse(s).workflow_runs;process.stdout.write(r&&r[0]?String(r[0].id):"");}catch{process.stdout.write("");}})')" ||
    ops_die "GitHub API call failed (bad or expired token?)"
  [ -n "$run_id" ] ||
    ops_die "no successful ${FORK_WORKFLOW_FILE} run found. Push to the release branch or start it from the Actions tab, then retry."

  # Read name and URL together so a run whose artifact already expired is reported
  # as such instead of failing later on an empty URL.
  local meta
  meta="$(curl -fsSL -H "Authorization: Bearer ${token}" \
    -H "Accept: application/vnd.github+json" \
    "${api}/actions/runs/${run_id}/artifacts" |
    node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const a=(JSON.parse(s).artifacts||[]).filter(x=>!x.expired);process.stdout.write(a[0]?a[0].name+"\t"+a[0].archive_download_url:"");}catch{process.stdout.write("");}})')" ||
    ops_die "could not list artifacts of run ${run_id}"
  name="${meta%%$'\t'*}"
  url="${meta#*$'\t'}"
  [ -n "$name" ] && [ -n "$url" ] ||
    ops_die "run ${run_id} has no unexpired artifact left (retention window passed). Re-run the workflow."

  tmp="$(mktemp -d)"
  out="$tmp/${name}.zip"
  ops_log "downloading artifact ${name} from run ${run_id}"
  curl -fsSL --retry 3 --retry-delay 2 -H "Authorization: Bearer ${token}" \
    -o "$out" "$url" || ops_die "artifact download failed"
  printf '%s' "$out"
}

resolve_tarball() {
  local src="$1" tmp out dist_entries
  # Accept an https:// URL so a hand-copied artifact/asset link can skip the
  # download-then-scp dance entirely. (--from-ci does the lookup for you; this is the
  # escape hatch when you already have a URL.)
  case "$src" in
    http://* | https://*)
      ops_require_cmd curl
      tmp="$(mktemp -d)"
      out="$tmp/$(basename "${src%%\?*}")"
      ops_log "downloading $src"
      curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$src" ||
        ops_die "download failed: $src"
      src="$out"
      ;;
  esac
  [ -f "$src" ] || ops_die "tarball not found: $src"
  case "$src" in
    *.zip)
      ops_require_cmd unzip
      tmp="$(mktemp -d)"
      unzip -q -o "$src" -d "$tmp" || ops_die "could not unzip $src"
      # Not `find ... | head -1`: head leaves after the first line, find takes SIGPIPE
      # and pipefail turns that into a spurious failure. -print -quit stops find itself.
      out="$(find "$tmp" -type f -name '*.tgz' -print -quit)"
      [ -n "$out" ] || ops_die "no .tgz inside $src (expected the packed tarball from the Build Fork Tarball workflow)"
      ;;
    *.tgz | *.tar.gz) out="$src" ;;
    *) ops_die "expected a .tgz or the GitHub artifact .zip, got: $src" ;;
  esac
  # A tarball without dist/ would make npm try to build on this host, which is the
  # exact failure --tarball exists to avoid, so reject it before touching the install.
  # Count over the whole listing instead of `| grep -q`: grep -q exits on its first
  # match, tar then dies of SIGPIPE (141), and `set -o pipefail` would turn that into a
  # false "ships no dist/" rejection of a perfectly good tarball. grep -c reads to EOF,
  # and `|| true` absorbs its exit 1 on zero matches.
  dist_entries="$(tar -tzf "$out" | grep -c '^package/dist/' || true)"
  [ "${dist_entries:-0}" -gt 0 ] ||
    ops_die "$src ships no dist/; it would require a local build. Rebuild it with the Build Fork Tarball workflow."
  printf '%s' "$out"
}

install_tarball() {
  local tgz="$1"
  ops_log "installing prebuilt tarball globally (npm install -g)"
  npm install -g "$tgz"
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
  # Capture first, then trim. Piping straight into `head -20` lets head exit early,
  # kill the producer with SIGPIPE and (under pipefail) trip the || branch, which would
  # print "could not list plugins" over a listing that actually succeeded.
  local plugin_out
  if plugin_out="$(omniroute plugin list 2>&1)"; then
    printf '%s\n' "$plugin_out" | sed -n '1,20p' >&2
  else
    ops_log "  (could not list plugins; check 'omniroute status')"
  fi
}

if [ "$DO_ROLLBACK" -eq 1 ]; then
  [ -f "$STATE_FILE" ] || ops_die "no rollback state at $STATE_FILE (nothing recorded yet)"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  : "${PREV_SHA:?state file is missing PREV_SHA}"
  ops_log "rolling back to $PREV_SHA (previous global version: ${PREV_VERSION:-unknown})"
  [ "$ASSUME_YES" -eq 1 ] || ops_confirm "Rebuild and reinstall commit $PREV_SHA?"
  assert_node_supported
  omniroute stop >/dev/null 2>&1 || true
  # Rebuilding is impossible on a low-memory host, so reuse the archived tarball
  # when the previous install came from one.
  if [ -n "${PREV_TARBALL:-}" ] && [ -f "${PREV_TARBALL:-}" ]; then
    ops_log "reinstalling archived tarball: $PREV_TARBALL"
    install_tarball "$PREV_TARBALL"
  else
    [ -z "${PREV_TARBALL:-}" ] ||
      ops_log "WARNING: archived tarball $PREV_TARBALL is gone; falling back to a source rebuild"
    git -C "$REPO_ROOT" checkout --quiet --detach "$PREV_SHA"
    build_and_install
  fi
  restart_server || true
  verify
  ops_log "rollback complete. Data was not modified by the install itself;"
  ops_log "restore ${SNAPSHOT_ID:-<snapshot-id>} with bin/restore-data.sh only if the DB was migrated."
  exit 0
fi

assert_node_supported

if [ "$FROM_CI" = "1" ]; then
  [ -z "$TARBALL" ] || ops_die "--from-ci and --tarball are mutually exclusive"
  TARBALL="$(fetch_ci_tarball)"
fi

# Fail before the download, not after: --from-ci pulls hundreds of MB, and dying
# afterwards on a missing git dir would waste all of it.
if [ -z "$TARBALL" ] && ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  ops_die "$REPO_ROOT is not a git clone; source mode needs one. Use --tarball <file|url> or --from-ci."
fi

RESOLVED_TARBALL=""
[ -z "$TARBALL" ] || RESOLVED_TARBALL="$(resolve_tarball "$TARBALL")"

CURRENT_VERSION="$(global_version)"
ops_log "repo:           $REPO_ROOT"
ops_log "data dir:       $OMNIROUTE_DATA_DIR"
ops_log "global version: $CURRENT_VERSION"

# In tarball mode the git state is informational only -- nothing is fetched, checked
# out or built from it -- so a missing//shallow clone must not abort the install.
TARGET_REF=""
CURRENT_SHA=""
if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  TARGET_REF="$(resolve_target_ref)"
  CURRENT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  ops_log "target ref:     $TARGET_REF"
  ops_log "current commit: $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
else
  ops_log "current commit: (not a git clone; tarball mode)"
fi
[ -z "$TARBALL" ] || ops_log "tarball:        $RESOLVED_TARBALL"

TARGET_SHA="$CURRENT_SHA"
if [ -n "$TARBALL" ]; then
  # No build and no checkout happen, so a dirty tree and stale refs cannot affect
  # the result: the tarball alone determines what gets installed.
  ops_log "tarball mode: skipping fetch, checkout and build"
  [ "$ASSUME_YES" -eq 1 ] || ops_confirm "Install $RESOLVED_TARBALL as the global omniroute?"
else
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
    # Capture then trim: `git log | head -15` lets head exit early and kill git with
    # SIGPIPE, which under pipefail trips the `|| true` and silently drops the log.
    local_log="$(git -C "$REPO_ROOT" --no-pager log --oneline "$CURRENT_SHA..$TARGET_SHA" 2>/dev/null || true)"
    [ -z "$local_log" ] || printf '%s\n' "$local_log" | sed -n '1,15p' >&2
  fi

  [ "$ASSUME_YES" -eq 1 ] || ops_confirm "Build $TARGET_REF and replace the global omniroute install?"
fi

SNAPSHOT_ID=""
if [ "$DO_SNAPSHOT" -eq 1 ]; then
  ops_log "snapshotting data dir"
  SNAPSHOT_ID="$("$REPO_ROOT/bin/snapshot-data.sh" --label pre-update --data-dir "$OMNIROUTE_DATA_DIR")"
  ops_log "snapshot id: $SNAPSHOT_ID"
else
  ops_log "skipping snapshot (--skip-snapshot)"
fi

# Read before the state file is overwritten: the tarball installed last time is the
# one --rollback needs to reinstall.
PRIOR_TARBALL=""
[ ! -f "$STATE_FILE" ] || PRIOR_TARBALL="$(sed -n 's/^INSTALLED_TARBALL=//p' "$STATE_FILE" | tail -1)"

# Keep the tarball around: on a host that cannot build, an archived copy is the only
# way back to the previous version.
ARCHIVED_TARBALL=""
if [ -n "$TARBALL" ]; then
  mkdir -p "$OMNIROUTE_DATA_DIR/tarballs"
  ARCHIVED_TARBALL="$OMNIROUTE_DATA_DIR/tarballs/$(date -u +%Y%m%dT%H%M%SZ)-$(basename "$RESOLVED_TARBALL")"
  cp "$RESOLVED_TARBALL" "$ARCHIVED_TARBALL"
  ops_log "archived tarball: $ARCHIVED_TARBALL"
fi

# Recorded before the checkout so --rollback targets the exact commit that was
# known-good, regardless of where the ref points later.
mkdir -p "$OMNIROUTE_DATA_DIR"
{
  printf 'PREV_SHA=%s\n' "${CURRENT_SHA:-unknown}"
  printf 'PREV_VERSION=%s\n' "$CURRENT_VERSION"
  printf 'UPDATED_TO=%s\n' "$TARGET_SHA"
  printf 'UPDATED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -n "$PRIOR_TARBALL" ] && printf 'PREV_TARBALL=%s\n' "$PRIOR_TARBALL"
  [ -n "$ARCHIVED_TARBALL" ] && printf 'INSTALLED_TARBALL=%s\n' "$ARCHIVED_TARBALL"
  [ -n "$SNAPSHOT_ID" ] && printf 'SNAPSHOT_ID=%s\n' "$SNAPSHOT_ID"
} >"$STATE_FILE"

ops_log "stopping server"
omniroute stop >/dev/null 2>&1 || ops_log "  (server was not running)"

if [ -n "$TARBALL" ]; then
  install_tarball "$ARCHIVED_TARBALL"
else
  git -C "$REPO_ROOT" checkout --quiet --detach "$TARGET_SHA"
  build_and_install
fi

restart_server || true
verify

if [ -n "$TARBALL" ]; then
  ops_log "update complete from tarball: $(basename "$RESOLVED_TARBALL")"
else
  ops_log "update complete: $(git -C "$REPO_ROOT" rev-parse --short "$TARGET_SHA")"
fi
ops_log "rollback with: bin/update-from-fork.sh --rollback"
