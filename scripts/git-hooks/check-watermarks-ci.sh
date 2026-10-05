#!/usr/bin/env bash
# CI backstop for AI-attribution watermarks (see lib-watermark.sh).
#
# The pre-commit/commit-msg hooks only run in a checkout that has
# core.hooksPath pointed at scripts/git-hooks — a fresh clone or worktree
# doesn't get that until someone runs `mix setup` (or `git.hooks.install`)
# in it, so a commit made before that step, or from a tool that bypasses
# hooks, can still slip a watermark into history. This script is the
# independent check that catches that regardless of local hook state: it
# re-scans every commit message AND the full diff content in the PR range,
# and fails CI if a watermark survived.
set -euo pipefail

hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-watermark.sh
source "$hook_dir/lib-watermark.sh"

regex="$(watermark_regex)"

# Range to check: in a PR, compare against the merge-base with the target
# branch; on a direct push, just the pushed commits. GITHUB_BASE_REF is set
# for pull_request events.
if [ -n "${GITHUB_BASE_REF:-}" ]; then
  git fetch -q origin "${GITHUB_BASE_REF}" --depth=50 2>/dev/null || true
  base="$(git merge-base "origin/${GITHUB_BASE_REF}" HEAD 2>/dev/null || echo "")"
else
  base="${BEFORE_SHA:-HEAD~1}"
fi

if [ -z "$base" ] || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  echo "check-watermarks-ci: no usable base commit found, scanning HEAD only"
  base="HEAD~1"
fi

status=0

echo "== Scanning commit messages (${base}..HEAD) =="
while IFS= read -r sha; do
  [ -z "$sha" ] && continue
  msg="$(git log -1 --format='%B' "$sha")"
  if grep -Eq "$regex" <<< "$msg"; then
    echo "::error::Commit $sha carries an AI-attribution watermark in its message:"
    grep -E "$regex" <<< "$msg" | sed 's/^/    /'
    status=1
  fi
done < <(git rev-list "${base}..HEAD")

echo "== Scanning diff content (${base}..HEAD) =="
diff_hits="$(git diff "${base}...HEAD" -- . ':!scripts/git-hooks' | grep -E "^\+" | grep -Ev '^\+\+\+' | grep -E "$regex" || true)"
if [ -n "$diff_hits" ]; then
  echo "::error::Diff introduces AI-attribution watermark line(s):"
  echo "$diff_hits" | sed 's/^/    /'
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "No AI-attribution watermarks found."
fi

exit "$status"
