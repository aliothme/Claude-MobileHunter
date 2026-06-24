#!/usr/bin/env bash
# One-shot: stamp your GitHub username / display name / repo name into the repo,
# replacing the __GH_USER__ / __AUTHOR__ / __REPO__ placeholders.
#
#   ./finalize.sh <github-username> "<Display Name>" [repo-name]
#
# Example:
#   ./finalize.sh alioth "Alioth" Claude-MobileHunter
set -euo pipefail
GH_USER="${1:?github username required}"
AUTHOR="${2:?display name required}"
REPO="${3:-Claude-MobileHunter}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# edit tracked text files only; skip .git and this script
grep -rlZ --exclude-dir=.git -e '__GH_USER__' -e '__AUTHOR__' -e '__REPO__' "$HERE" \
  | while IFS= read -r -d '' f; do
      [ "$f" = "$HERE/finalize.sh" ] && continue
      sed -i "s|__GH_USER__|$GH_USER|g; s|__AUTHOR__|$AUTHOR|g; s|__REPO__|$REPO|g" "$f"
      echo "stamped $f"
    done
echo "Done. Verify with: grep -rn '__GH_USER__\\|__AUTHOR__\\|__REPO__' . --exclude-dir=.git || echo clean"
