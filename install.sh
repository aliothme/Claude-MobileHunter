#!/usr/bin/env bash
# Manual installer for Claude-MobileHunter (use this if you don't install via the
# Claude Code plugin marketplace). Copies the /hunt-mobile command and all mhunt-*
# skills into your user-level ~/.claude/ so they're available in every project.
#
#   ./install.sh              install (copy)
#   ./install.sh --link       install via symlink (stays in sync with this repo)
#   ./install.sh --uninstall  remove what this script installed
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${CLAUDE_HOME:-$HOME/.claude}"
CMD="hunt-mobile.md"

uninstall() {
  rm -f "$DEST/commands/$CMD"
  rm -rf "$DEST"/skills/mhunt-*
  echo "Removed /hunt-mobile command and mhunt-* skills from $DEST"
}

install() {
  local mode="${1:-copy}"
  mkdir -p "$DEST/commands" "$DEST/skills"
  if [ "$mode" = "link" ]; then
    ln -sfn "$SRC/commands/$CMD" "$DEST/commands/$CMD"
    for d in "$SRC"/skills/mhunt-*; do ln -sfn "$d" "$DEST/skills/$(basename "$d")"; done
    echo "Symlinked command + $(ls -d "$SRC"/skills/mhunt-* | wc -l) skills into $DEST"
  else
    cp "$SRC/commands/$CMD" "$DEST/commands/$CMD"
    cp -r "$SRC"/skills/mhunt-* "$DEST/skills/"
    echo "Copied command + $(ls -d "$SRC"/skills/mhunt-* | wc -l) skills into $DEST"
  fi
  echo "Done. Run /hunt-mobile <app.apk|app.ipa> inside Claude Code."
}

case "${1:-}" in
  --uninstall) uninstall ;;
  --link)      install link ;;
  ""|--copy)   install copy ;;
  *) echo "usage: $0 [--copy|--link|--uninstall]"; exit 1 ;;
esac
