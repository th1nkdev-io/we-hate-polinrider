#!/usr/bin/env bash
# inspect-repo-vectors.sh — montre le CONTENU des vecteurs que les nettoyeurs ne traitent pas seuls :
# .vscode/settings.json, workflows GitHub, fichiers « security-guard* » et fichiers IoC classiques.
# LECTURE SEULE. Affiche au plus 300 caracteres par ligne (evite de deverser un payload dans le terminal).
#
# Usage :  bash detect/inspect-repo-vectors.sh [DEPOT_OU_DOSSIER ...]     (defaut : dossier courant)
# Astuce : un fichier security-guard* qui cite des signatures est en general une GARDE DEFENSIVE
#          (elle contient ce qu'elle traque). Lire avant de conclure ; ne pas supprimer d'office.
set -uo pipefail

[ "$#" -gt 0 ] || set -- .
SIG='A10-\*40840|folderOpen|runOn|_0x[0-9a-f]{4,}|vercel\.app|global\[|global\.i|temp_auto_push|eval\(|child_process|https?://[0-9]'

SHOWN=$'\n'
show() {  # $1 = fichier (chaque fichier n'est affiche qu'une fois)
  local f="$1"
  [ -f "$f" ] || return
  case "$SHOWN" in *$'\n'"$f"$'\n'*) return ;; esac
  SHOWN+="$f"$'\n'
  echo "   -- $f  ($(wc -c <"$f") o) --"
  echo -n "      marqueurs : "; grep -aoE "$SIG" "$f" 2>/dev/null | sort -u | tr '\n' ' '; echo
  echo "      apercu (300 c./ligne max) :"
  cut -c1-300 "$f" 2>/dev/null | head -25 | sed 's/^/        /'
}

for d in "$@"; do
  d="${d/#\~/$HOME}"
  [ -d "$d" ] || { echo "(absent : $d)"; continue; }
  echo "======================================================================"
  echo "### $d"
  show "$d/.vscode/settings.json"
  show "$d/.vscode/tasks.json"
  if [ -d "$d/.github/workflows" ]; then
    for wf in "$d"/.github/workflows/*; do show "$wf"; done
  fi
  while IFS= read -r g; do show "$g"; done < <(find "$d" \
      \( -name node_modules -o -name .git \) -prune -o -iname '*security-guard*' -type f -print 2>/dev/null)
  for extra in config.bat temp_auto_push.bat temp_interactive_push.bat branch_structure.json spellright.dict; do
    while IFS= read -r x; do show "$x"; done < <(find "$d" \
        \( -name node_modules -o -name .git \) -prune -o -name "$extra" -type f -print 2>/dev/null)
  done
done
echo "======================================================================"
echo "Fini."
