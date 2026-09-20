#!/usr/bin/env bash
# diag-repo.sh — « ou est passe mon travail ? » : diagnostic LECTURE SEULE d'un clone apres un incident.
# Regarde ce que la sauvegarde RESCUE a capture, l'etat du clone, le reflog, et cherche d'autres copies.
#
# Usage :
#   bash rescue/diag-repo.sh <clone> [dossier_RESCUE] [motif]
#     clone          chemin du clone a examiner
#     dossier_RESCUE dossier des bundles/patches (defaut : ~/_Workspace/RESCUE_SLIM)
#     motif          fragment du nom du projet (defaut : nom du dossier du clone)
# Ne modifie rien.
set -uo pipefail

CLONE="${1:-}"
[ -n "$CLONE" ] || { sed -n '2,10p' "$0"; exit 1; }
CLONE="${CLONE/#\~/$HOME}"
RESCUE="${2:-$HOME/_Workspace/RESCUE_SLIM}"
PAT="${3:-$(basename "$CLONE")}"

echo "=== 1. Ce que RESCUE a capture pour « $PAT » ($RESCUE) ==="
ls -la "$RESCUE"/*"$PAT"* 2>/dev/null || echo "   aucun fichier RESCUE pour ce motif"

echo ""
echo "=== 2. Etat du clone : $CLONE ==="
if [ -d "$CLONE/.git" ] || [ -f "$CLONE/HEAD" ]; then
  cd "$CLONE" || exit 1
  echo "-- dernier commit present --"
  git log -1 --format='%h  %ci  %s'
  echo "-- branches (locales + distantes) --"
  git branch -a
  echo "-- reflog (commits parfois « perdus » mais encore la) --"
  git reflog -15 2>/dev/null | head -15
  echo "-- modifs non commitees --"
  git status --short
  echo "-- commits locaux en avance sur origin --"
  git log --oneline origin/HEAD..HEAD 2>/dev/null | head || echo "   (aucun / origin/HEAD non defini)"
  echo "-- stashes --"
  git stash list 2>/dev/null | head
else
  echo "   clone introuvable a ce chemin"
fi

echo ""
echo "=== 3. Une autre copie du projet sur le disque ? ==="
find "$HOME" -maxdepth 6 -type d -iname "*${PAT}*" -not -path '*/node_modules/*' 2>/dev/null | head

echo ""
echo "=== 4. Dossiers .git portant ce nom, ailleurs (recherche large) ==="
find "$HOME" -maxdepth 7 -type d -name '.git' -not -path '*/node_modules/*' 2>/dev/null \
  | while read -r g; do
      d="$(dirname "$g")"
      case "$d" in *"$PAT"*) echo "   -> $d";; esac
    done | head
