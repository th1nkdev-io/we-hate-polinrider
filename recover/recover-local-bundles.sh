#!/usr/bin/env bash
# recover-local-bundles.sh — recupere des PROJETS depuis leurs bundles RESCUE (typiquement les projets
# purement locaux, sans remote GitHub). Le bundle est la seule source : on le clone, on coche une branche,
# puis on greffe les modifs non commitees (.uncommitted.patch) et les fichiers non suivis (.untracked.tgz).
# N'ecrase rien d'existant : ecrit dans un dossier neuf.
#
# Usage :
#   bash recover/recover-local-bundles.sh [DOSSIER_RESCUE] [DOSSIER_DESTINATION]
#     DOSSIER_RESCUE       defaut : ~/_Workspace/RESCUE_SLIM
#     DOSSIER_DESTINATION  defaut : ~/_Workspace/_RECUPERE
#   ALL=1 bash recover/recover-local-bundles.sh     # tous les bundles (defaut : seulement ceux dont le
#                                                   # remote est VIDE dans _manifest.tsv, s'il existe)
# Ne fait AUCUN acces reseau.
set -uo pipefail

RESCUE="${1:-$HOME/_Workspace/RESCUE_SLIM}"; RESCUE="${RESCUE/#\~/$HOME}"
DEST="${2:-$HOME/_Workspace/_RECUPERE}";      DEST="${DEST/#\~/$HOME}"
MANIFEST="$RESCUE/_manifest.tsv"
[ -d "$RESCUE" ] || { echo "Dossier RESCUE introuvable : $RESCUE"; exit 1; }
mkdir -p "$DEST"

# Liste des bases a traiter : colonne 1 du manifeste si la colonne 2 (remote) est vide, sinon tous les *.bundle
bases=()
if [ -f "$MANIFEST" ] && [ "${ALL:-0}" != "1" ]; then
  while IFS=$'\t' read -r base remote _; do
    [ -n "${base:-}" ] && [ -z "${remote:-}" ] && bases+=("$base")
  done < "$MANIFEST"
else
  for b in "$RESCUE"/*.bundle; do
    [ -e "$b" ] || continue
    n="$(basename "$b" .bundle)"
    case "$n" in *.stash) continue ;; esac
    bases+=("$n")
  done
fi
[ "${#bases[@]}" -gt 0 ] || { echo "Aucun projet a recuperer."; exit 0; }

for base in "${bases[@]}"; do
  bundle="$RESCUE/$base.bundle"
  dest="$DEST/$base"
  echo "======== $base ========"
  [ -s "$bundle" ] || { echo "  pas de bundle non vide — saute"; continue; }
  [ -e "$dest" ] && { echo "  $dest existe deja — saute (rien n'est ecrase)"; continue; }

  git clone -q "$bundle" "$dest" 2>/dev/null || { echo "  clone du bundle echoue"; continue; }
  # coche une vraie branche (le HEAD du bundle peut pointer vers une ref absente)
  br="$(git -C "$dest" branch -r 2>/dev/null | grep -v -- '->' | sed 's|.*origin/||;s/^ *//' | head -1)"
  if [ -n "$br" ]; then
    git -C "$dest" checkout -q -B "$br" "origin/$br" 2>/dev/null || git -C "$dest" checkout -q "$br" 2>/dev/null
  fi
  # ce « remote » pointe vers le fichier bundle : on le retire
  git -C "$dest" remote remove origin 2>/dev/null || true

  patch="$RESCUE/$base.uncommitted.patch"
  if [ -s "$patch" ]; then
    if git -C "$dest" apply --3way "$patch" 2>/dev/null; then echo "  + modifs non commitees appliquees"
    else git -C "$dest" apply --reject "$patch" 2>/dev/null; echo "  + modifs non commitees : CONFLITS (.rej a revoir)"; fi
  fi
  tgz="$RESCUE/$base.untracked.tgz"
  if [ -s "$tgz" ]; then
    tar xzf "$tgz" -C "$dest" --skip-old-files 2>/dev/null && echo "  + fichiers non suivis restaures"
  fi

  b="$(git -C "$dest" rev-parse --abbrev-ref HEAD 2>/dev/null)"
  c="$(git -C "$dest" rev-list --count --all 2>/dev/null)"
  f="$(git -C "$dest" ls-files 2>/dev/null | wc -l)"
  echo "  branche: ${b:-?}   commits: ${c:-0}   fichiers suivis: ${f:-0}"
  git -C "$dest" log -1 --format='  dernier commit: %ci  %s' 2>/dev/null || echo "  (aucun commit coche)"
done

echo ""
echo "Projets recuperes dans : $DEST"
echo "AVANT de les ouvrir dans un IDE : python3 detect/scan-workspace.py \"$DEST\" et detect/scan-git-history.py --root \"$DEST\""
echo "Puis creez un depot prive et poussez-les pour ne plus les perdre (recover/push-recovered.sh)."
