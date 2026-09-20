#!/usr/bin/env bash
# push-recovered.sh — cree un depot GitHub PRIVE pour chaque projet recupere et y pousse la branche courante.
# ACTION VISIBLE A L'EXTERIEUR : SIMULATION par defaut ; rien n'est cree ni pousse sans --yes.
#
# Usage :
#   bash recover/push-recovered.sh PROPRIETAIRE DOSSIER_PROJETS [nom ...]              # simulation
#   bash recover/push-recovered.sh --yes PROPRIETAIRE DOSSIER_PROJETS [nom ...]        # cree + pousse
#     PROPRIETAIRE     compte ou organisation GitHub (ex. mon-compte)
#     DOSSIER_PROJETS  dossier contenant un sous-dossier par projet (ex. ~/_Workspace/_RECUPERE)
#     nom ...          limite aux sous-dossiers indiques (defaut : tous ceux qui sont des depots git)
#   PREFIX=recup- bash recover/push-recovered.sh ...     # prefixe optionnel pour le nom du depot distant
#
# Prerequis : `gh auth status` OK avec un jeton NEUF (jamais un jeton d'avant l'incident).
# Relancable : si le depot distant existe deja, ajoute juste le remote et pousse.
# Verifiez d'abord chaque projet (detect/scan-workspace.py + detect/scan-git-history.py) : ne poussez jamais un
# historique qui contient encore le payload.
set -uo pipefail

GO=0
[ "${1:-}" = "--yes" ] && { GO=1; shift; }
OWNER="${1:-}"; BASE="${2:-}"
[ -n "$OWNER" ] && [ -n "$BASE" ] || { sed -n '2,16p' "$0"; exit 1; }
BASE="${BASE/#\~/$HOME}"
shift 2
PREFIX="${PREFIX:-}"

if [ "$#" -gt 0 ]; then names=("$@"); else
  names=(); for d in "$BASE"/*/; do [ -d "${d}.git" ] && names+=("$(basename "$d")"); done
fi
[ "${#names[@]}" -gt 0 ] || { echo "Aucun projet git dans $BASE"; exit 0; }
[ "$GO" -eq 1 ] && ! gh auth status >/dev/null 2>&1 && { echo "gh non authentifie (gh auth login)"; exit 1; }

for name in "${names[@]}"; do
  dir="$BASE/$name"; repo="$PREFIX$name"
  echo "======== $name -> $OWNER/$repo (prive) ========"
  [ -d "$dir/.git" ] || { echo "  pas un depot git — saute"; continue; }
  cd "$dir" || continue
  br="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
  echo "  branche : $br"
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "  modifs non commitees presentes — elles NE seront PAS poussees (git add -A && git commit a faire vous-meme)."
  fi
  [ "$GO" -eq 1 ] || { echo "  (simulation)"; continue; }
  if git remote get-url origin >/dev/null 2>&1; then
    echo "  remote origin deja present -> push"
    git push -u origin "$br" 2>&1 | tail -2 | sed 's/^/  /'
  elif ! gh repo create "$OWNER/$repo" --private --source=. --remote=origin --push 2>&1 | tail -3 | sed 's/^/  /'; then
    echo "  echec gh repo create (depot deja existant ? droits ?) — a faire a la main"
  fi
done
echo ""
[ "$GO" -eq 1 ] && echo "Fini. Verifiez sur GitHub que chaque depot est bien cree et a jour." \
                || echo "SIMULATION. Rien cree, rien pousse. Relancez avec --yes apres verification."
