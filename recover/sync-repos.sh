#!/usr/bin/env bash
# sync-repos.sh — reclone en masse tous tes dépôts depuis GitHub sur une machine
# PROPRE, après une compromission (jamais copier depuis la machine infectée).
#
# Prérequis : GitHub CLI (`gh auth login` déjà fait) + git.
# Lecture seule côté GitHub (ne fait que cloner). Relançable : saute ce qui est déjà là.
#
# Réglages ci-dessous :
set -uo pipefail

WORKSPACE="${WORKSPACE:-$HOME/_Workspace}"   # où cloner
PRIORITY=()                                   # comptes/orgs à cloner en premier, ex: ("moncompte" "mon-org")
DENY='^$'                                      # regex de dépôts à ignorer, ex: 'ancien-client|projet-mort'
SKIP=()                                        # noms de dépôts précis à sauter
SHALLOW=1                                       # 1 = clone léger (--depth 1, économe en data) ; 0 = historique complet
TIMEOUT=240                                     # secondes max par dépôt avant d'abandonner

mkdir -p "$WORKSPACE"

# comptes = ton compte + toutes tes organisations, priorités en tête
ALL=("$(gh api user --jq '.login' 2>/dev/null)")
while read -r org; do [ -n "$org" ] && ALL+=("$org"); done < <(gh api user/orgs --jq '.[].login' 2>/dev/null || true)
OWNERS=("${PRIORITY[@]}")
for o in "${ALL[@]}"; do
  [ -z "$o" ] && continue
  s=0; for p in "${OWNERS[@]}"; do [ "$o" = "$p" ] && s=1; done
  [ $s -eq 0 ] && OWNERS+=("$o")
done

in_skip(){ for x in "${SKIP[@]:-}"; do [ "$1" = "$x" ] && return 0; done; return 1; }
DEPTH=(); [ "$SHALLOW" = "1" ] && DEPTH=(-- --depth 1 --quiet)

echo "Comptes : ${OWNERS[*]}"; echo ""
for OWNER in "${OWNERS[@]}"; do
  echo "===== $OWNER ====="; mkdir -p "$WORKSPACE/$OWNER"
  gh repo list "$OWNER" --limit 500 --json name,nameWithOwner,isFork,isArchived \
    --jq '.[] | select(.isArchived==false and .isFork==false) | [.name,.nameWithOwner] | @tsv' \
  | while IFS=$'\t' read -r name nwo; do
      echo "$name" | grep -iqE "$DENY" && { echo "  [ignore] $name"; continue; }
      in_skip "$name" && { echo "  [skip]   $name"; continue; }
      dest="$WORKSPACE/$OWNER/$name"
      [ -d "$dest/.git" ] && { echo "  [déjà là] $name"; continue; }
      [ -e "$dest" ] && rm -rf "$dest"
      echo -n "  [clone] $name … "
      if timeout --kill-after=10 "$TIMEOUT" gh repo clone "$nwo" "$dest" "${DEPTH[@]}" >/dev/null 2>&1; then
        echo "✓"; else echo "✗ (timeout/échec — sautée)"; rm -rf "$dest"; fi
    done
done
echo ""; echo "Fini → $WORKSPACE/<compte>/<dépôt>"
