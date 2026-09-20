#!/usr/bin/env bash
# commit-cleaned.sh — commite (et, si demande, pousse) le nettoyage du working tree dans une liste de depots.
# SIMULATION par defaut : montre les diffs, ne commite ni ne pousse rien.
#
# Usage :
#   bash recover/commit-cleaned.sh DEPOT [DEPOT ...]                 # simulation
#   bash recover/commit-cleaned.sh --yes DEPOT [DEPOT ...]           # commit LOCAL seulement
#   bash recover/commit-cleaned.sh --yes --push DEPOT [DEPOT ...]    # commit + push (action visible a l'exterieur)
#   MSG="mon message" bash recover/commit-cleaned.sh ...             # message personnalise
#
# ATTENTION : ce script nettoie le DERNIER commit, pas l'historique. Si l'infection est dans des commits
# deja pousses (verifier avec detect/scan-git-history.py), le payload reste accessible : ne poussez pas ici,
# suivez docs/prompt-nettoyage-depot.md (filter-repo + depot neuf).
# Ne commite que les fichiers DEJA suivis (git add -u) : jamais un .env ou un fichier non suivi par erreur.
set -uo pipefail

GO=0; PUSH=0; REPOS=()
for a in "$@"; do
  case "$a" in
    --yes) GO=1 ;;
    --push) PUSH=1 ;;
    *) REPOS+=("${a/#\~/$HOME}") ;;
  esac
done
[ "${#REPOS[@]}" -gt 0 ] || { sed -n '2,15p' "$0"; exit 1; }
[ "$PUSH" -eq 1 ] && [ "$GO" -eq 0 ] && { echo "--push exige --yes"; exit 1; }
MSG="${MSG:-security: retrait du payload PolinRider (fausse police, auto-exec tasks/settings, config bourree)}"

for d in "${REPOS[@]}"; do
  echo "======================================================================"
  echo "### $d"
  if [ ! -d "$d/.git" ]; then echo "   pas un depot git — saute"; continue; fi
  cd "$d" || continue
  br="$(git rev-parse --abbrev-ref HEAD)"
  echo "   branche : $br   remote : $(git remote get-url origin 2>/dev/null || echo '(aucun)')"
  echo "   -- fichiers suivis modifies/supprimes (seuls ceux-la seraient commites) --"
  git status --short --untracked-files=no | sed 's/^/   /'
  echo "   -- fichiers NON suivis (ne seront PAS commites) --"
  git status --short | grep '^??' | sed 's/^/   /' | head -15
  [ "$GO" -eq 1 ] || continue
  git add -u
  if git commit -q -m "$MSG"; then
    echo "   commit cree"
    if [ "$PUSH" -eq 1 ]; then
      if git push -q; then echo "   pousse sur origin/$br"; else echo "   push echoue — a refaire a la main"; fi
    fi
  else
    echo "   (rien a commiter)"
  fi
done
echo "======================================================================"
[ "$GO" -eq 1 ] && echo "Fini." || echo "SIMULATION. Rien commite. Relisez les diffs (git diff), puis relancez avec --yes."
