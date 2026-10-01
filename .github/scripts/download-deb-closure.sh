#!/usr/bin/env bash
# Download the .deb closure for one package list into a directory, for
# .github/workflows/ci-deps-image.yml to publish as a bundle. Ported from
# wolfSSL's .github/scripts/download-deb-closure.sh.
#
# Runs as root on the runner. apt downloads only what is not already
# installed, so the closure carries nothing the runner image preinstalls and
# is only installable on that same runner image.
#
# usage: download-deb-closure.sh <package-list> <dest-dir>
set -uo pipefail

LIST=${1:?package list}
DEST=${2:?destination directory}

mapfile -t PKGS < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST")
echo "Packages (${#PKGS[@]}): ${PKGS[*]}"
export DEBIAN_FRONTEND=noninteractive
mkdir -p "$DEST" && rm -f "$DEST"/*.deb
apt-get clean
# No wolfSSH job installs from the runner's Google/Microsoft apt repos, and a
# bad index on either fails apt-get update. Drop them.
grep -rlE 'dl\.google\.com|packages\.microsoft\.com' \
  /etc/apt/sources.list.d/ 2>/dev/null | xargs -r rm -vf || true
# apt drops a stalled connection after 30s and retries it, `timeout` kills a
# wedged apt-get, then retry() re-runs it.
APT_OPTS=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30
          -o Acquire::https::Timeout=30)
retry() { local i; for i in 1 2 3 4 5; do "$@" && return 0; sleep $((2**i)); done; "$@"; }
retry timeout -k 10 120 apt-get "${APT_OPTS[@]}" update -q
# One closure per package, so one unbundleable package cannot abort the rest;
# install-apt-deps falls back to apt for anything missing.
skipped=0
for pkg in "${PKGS[@]}"; do
  retry timeout -k 10 300 apt-get "${APT_OPTS[@]}" install -y --download-only "$pkg" \
    || { echo "::warning::could not download $pkg"; skipped=$((skipped+1)); }
done
cp /var/cache/apt/archives/*.deb "$DEST/" 2>/dev/null || true
# The index and image steps run unprivileged.
chown --reference="$DEST" "$DEST"/*.deb 2>/dev/null || true
echo "Bundled $(ls "$DEST"/*.deb 2>/dev/null | wc -l) .deb files ($(du -sh "$DEST" | cut -f1)); ${skipped} skipped"
test -n "$(ls "$DEST"/*.deb 2>/dev/null)"  # fail if nothing was bundled
