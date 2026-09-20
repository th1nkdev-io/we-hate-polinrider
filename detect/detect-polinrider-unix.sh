#!/usr/bin/env bash
# detect-polinrider-unix.sh
# Detecteur PolinRider pour Linux ET macOS — LECTURE SEULE (ne supprime/modifie/execute rien).
# N'execute AUCUN fichier scanne, ne lance ni git ni npm : tout est lu avec find/grep/awk/od.
# Usage :
#     chmod +x detect-polinrider-unix.sh
#     ./detect-polinrider-unix.sh            # scanne $HOME
#     ./detect-polinrider-unix.sh /chemin    # scanne un dossier precis
# Resultat : rapport ~/detect-polinrider.txt + verdict a l'ecran.
#   [!] HAUT  = indicateur fort (machine/depot a considerer comme compromis)
#   [?] MOYEN = parfois legitime : lire le fichier avant de conclure
# Pour une analyse plus fine (fichier:ligne, reflog git) : python3 detect/scan-workspace.py
# Script auditable : lisez-le avant de l'executer.
set -uo pipefail
ROOT="$(cd "${1:-$HOME}" 2>/dev/null && pwd -P)" || { echo "Dossier introuvable : ${1:-}"; exit 1; }
OUT="$HOME/detect-polinrider.txt"
FLAG=0; WARN=0
: > "$OUT"
echo "### DETECTION POLINRIDER — $(date) — $(hostname) — cible: $ROOT" >> "$OUT"

# Boite a outils elle-meme (elle CITE les marqueurs) : ses resultats textuels sont ignores.
SELF_ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd -P)"
[ -f "$SELF_ROOT/docs/indicators-of-compromise.md" ] || SELF_ROOT="/nonexistent"
notself(){ grep -v -F "$SELF_ROOT/"; }

# Dossiers exclus (dependances et sorties de build)
EXCL=(node_modules .git dist build out .next .nuxt .output .svelte-kit .vercel .turbo .cache
      .parcel-cache .angular coverage __pycache__ .venv venv .gradle Pods vendor target Caches)
# (compatible bash 3.2, celui de macOS : pas de mapfile)
or_names(){ OR=(); for n in "$@"; do [ ${#OR[@]} -gt 0 ] && OR+=(-o); OR+=(-name "$n"); done; }
or_names "${EXCL[@]}"; PRUNE=("${OR[@]}")
GREPX=(--exclude="$(basename "$OUT")"); for d in "${EXCL[@]}"; do GREPX+=(--exclude-dir="$d"); done
ff(){ find "$ROOT" \( -type d \( "${PRUNE[@]}" \) \) -prune -o "$@" -print 2>/dev/null; }

hit(){  FLAG=1; echo "  [!] HAUT  $1" | tee -a "$OUT"; }
warn(){ WARN=1; echo "  [?] MOYEN $1" | tee -a "$OUT"; }
section(){ echo "" >> "$OUT"; echo "== $1 ==" | tee -a "$OUT"; }

# --- IoC ---------------------------------------------------------------------
# Configs ciblees : charge AJOUTEE A LA FIN apres ~280 espaces, executee a l'import.
# postcss.config.mjs = cible n°1 (~62 %).
TARGETS=(postcss.config.mjs postcss.config.js postcss.config.ts postcss.config.cjs
  tailwind.config.js tailwind.config.ts tailwind.config.mjs tailwind.config.cjs
  eslint.config.mjs eslint.config.js eslint.config.cjs .eslintrc.js .eslintrc.cjs
  next.config.mjs next.config.js next.config.ts
  vite.config.js vite.config.mjs vite.config.ts vite.config.cjs
  webpack.config.js webpack.config.mjs webpack.config.ts
  astro.config.mjs astro.config.js astro.config.ts nuxt.config.ts nuxt.config.js nuxt.config.mjs
  svelte.config.js rollup.config.js babel.config.js babel.config.cjs
  gridsome.config.js vue.config.js truffle.js truffle-config.js)
ENTRIES=(App.js app.js index.js)
HIGH_MARKERS=(
  'rmcej%otb%' 'Cot%3t=shtP'                       # signatures v1 / v2
  '_$_1e42' 'MDy('                                 # decodeurs v1 / v2
  "global['!']" "global['_V']" 'global["!"]' 'global["_V"]'
  '2[gWfGj;<:-93Z^C' 'm6:tTh^D)cBz?NM]'            # cles XOR
  'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP' 'TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'   # TRON
  '0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e'       # Aptos
  '0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'       # Aptos
  'e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'           # UUID template StakingGame
  'A10-*40840'                                     # id de campagne, variante « global.i » (sept. 2026)
  'default-configuration.vercel.app' '260120.vercel.app'
  'vscode-settings-bootstrap.vercel.app' 'vscode-settings-config.vercel.app'
  'vscode-bootstrapper.vercel.app' 'vscode-load-config.vercel.app')
MED_MARKERS=(trongrid.io aptoslabs.com bsc-dataseed.binance.org bsc-rpc.publicnode)
C2_IPS='166\.88\.54\.158|198\.105\.127\.210|23\.27\.202\.27|154\.91\.0\.103|136\.0\.9\.8|166\.88\.4\.2|23\.27\.120\.142|202\.155\.8\.173|166\.88\.134\.82|188\.43\.33\.249|23\.27\.13\.43'
PKGS='tailwindcss-style-animate|tailwind-mainanimation|tailwind-autoanimation|tailwind-animationbased|tailwindcss-typography-style|tailwindcss-style-modify|tailwindcss-animate-style'

or_names "${TARGETS[@]}"; TGT_EXPR=("${OR[@]}")
or_names "${ENTRIES[@]}"; ENT_EXPR=("${OR[@]}")

# awk portable (mawk/BSD awk) : bourrage >=100 espaces en tete ou >=30 au milieu, suivi de code ;
# ligne >= 1000 car. Affiche "ligne N: raison". MINTAIL = longueur de code minimale apres le vide.
PAD_AWK='
function iscomment(t,  e){ # commentaire pur ? ("/*x*/ code" = du code, pas un commentaire)
  if (t ~ /^(\/\/|#)/ || t ~ /^\*[^\/]/) return 1
  if (t ~ /^\/\*/) { e=index(substr(t,3),"*/"); if (e==0) return 1; return (substr(t,e+4) ~ /^[ ;]*$/) }
  return 0 }
BEGIN{ s30=sprintf("%30s","") }
{ line=$0; gsub(/\t/," ",line)
  if (length(line) >= 1000) { print "ligne " NR ": " length(line) " caracteres"; }
  body=line; sub(/^ +/,"",body); lead=length(line)-length(body)
  if (lead >= 100 && length(body) >= MINTAIL && !iscomment(body)) { print "ligne " NR ": " lead " espaces en tete puis " length(body) " car. de code"; next }
  p=index(body,s30)
  if (p>1) { tail=substr(body,p); sub(/^ +/,"",tail)
    if (length(tail) >= MINTAIL && !iscomment(tail)) print "ligne " NR ": vide de >=30 espaces au milieu puis " length(tail) " car. de code" }
}'
fsize(){ wc -c < "$1" 2>/dev/null | tr -d ' '; }

# --- 1. Fichiers IoC ----------------------------------------------------------
section "1. Fichiers de propagation / leurres (temp_auto_push.bat, config.bat, branch_structure.json)"
while IFS= read -r f; do hit "temp_auto_push.bat (fiabilite ~100%) : $f"; done < <(ff -name 'temp_auto_push.bat')
while IFS= read -r f; do hit "branch_structure.json : $f"; done < <(ff -name 'branch_structure.json')
while IFS= read -r f; do
  if grep -qE 'LAST_COMMIT_DATE|commit --amend' "$f" 2>/dev/null; then hit "config.bat reecrit l'historique git : $f"
  else warn "config.bat (a relire) : $f"; fi
done < <(ff -name 'config.bat')
while IFS= read -r f; do hit "script de reecriture git (LAST_COMMIT_DATE) : $f"; done < <(
  grep -rlF "${GREPX[@]}" --include='*.bat' --include='*.cmd' --include='*.sh' --include='*.ps1' \
    -e 'LAST_COMMIT_DATE' "$ROOT" 2>/dev/null | notself)

# --- 2. Configs ciblees : bourrage d'espaces, lignes longues, taille ----------
section "2. Configs ciblees (postcss n°1, tailwind, eslint, next, vite, webpack, astro, nuxt...)"
while IFS= read -r f; do
  awk -v MINTAIL=20 "$PAD_AWK" "$f" 2>/dev/null | head -3 | while IFS= read -r l; do hit "charge dissimulee : $f : $l"; done
  s=$(fsize "$f"); [ "${s:-0}" -ge 3000 ] && warn "config de $s octets (saine ~80-200, infectee ~5000) : $f"
done < <(ff -type f \( "${TGT_EXPR[@]}" \))
while IFS= read -r f; do   # App.js / index.js : tres courants -> queue de code >= 100 car.
  awk -v MINTAIL=100 "$PAD_AWK" "$f" 2>/dev/null | grep -v 'caracteres$' | head -3 | while IFS= read -r l; do hit "charge dissimulee (entree) : $f : $l"; done
done < <(ff -type f \( "${ENT_EXPR[@]}" \))

# --- 3. Marqueurs de la charge -----------------------------------------------
section "3. Marqueurs (signatures, decodeurs, globales, cles XOR, adresses crypto, UUID, C2 Vercel)"
GE=(); for m in "${HIGH_MARKERS[@]}"; do GE+=(-e "$m"); done
while IFS= read -r l; do hit "marqueur : $l"; done < <(
  grep -rnIoF "${GREPX[@]}" "${GE[@]}" "$ROOT" 2>/dev/null | notself | sort -u)
while IFS= read -r l; do hit "tag de version / URL C2 : $l"; done < <(
  grep -rnIoE "${GREPX[@]}" -e "global\[['\"]_V['\"]\] *= *['\"]8-st[0-9]+" -e '\.vercel\.app/settings/(mac|linux|win)' \
    "$ROOT" 2>/dev/null | notself | sort -u)

section "4. Domaines blockchain et IP C2 (MOYEN : parfois legitimes)"
GE=(); for m in "${MED_MARKERS[@]}"; do GE+=(-e "$m"); done
while IFS= read -r l; do warn "domaine blockchain : $l"; done < <(
  grep -rnIoF "${GREPX[@]}" "${GE[@]}" "$ROOT" 2>/dev/null | notself | sort -u)
while IFS= read -r l; do warn "IP C2 connue : $l"; done < <(
  grep -rnIoE "${GREPX[@]}" "(^|[^0-9.])($C2_IPS)([^0-9.]|$)" "$ROOT" 2>/dev/null | notself | sort -u)

# --- 5. Paquets npm pieges ----------------------------------------------------
section "5. Paquets npm pieges (package.json + lockfiles + node_modules)"
while IFS= read -r l; do hit "paquet piege : $l"; done < <(
  grep -rnoE "${GREPX[@]}" --include='package.json' --include='package-lock.json' --include='npm-shrinkwrap.json' \
    --include='yarn.lock' --include='pnpm-lock.yaml' --include='bun.lock' \
    "(^|[^A-Za-z0-9_@/.-])($PKGS)([^A-Za-z0-9_-]|$)" "$ROOT" 2>/dev/null | notself | sort -u)
for p in ${PKGS//|/ }; do
  find "$ROOT" -type d -path "*/node_modules/$p" -prune -print 2>/dev/null | while IFS= read -r d; do hit "paquet piege installe : $d"; done
done

# --- 6. Fausses polices (signature binaire, JAMAIS le nom) ---------------------
section "6. Fausses polices .woff2/.woff/.ttf/.otf/.eot (verif. magic bytes)"
while IFS= read -r f; do
  [ -s "$f" ] || continue   # fichier vide : pas une charge
  case "$f" in
    *.eot|*.EOT) sig=$(od -An -tx1 -j34 -N2 "$f" 2>/dev/null | tr -d ' \n'); [ "$sig" = "4c50" ] && continue ;;
    *) sig=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
       case "$sig" in 774f4632|774f4646|00010000|4f54544f|74727565|74746366) continue ;; esac ;;
  esac
  hit "fausse police (octets '$sig', pas une police) : $f"
done < <(ff -type f \( -iname '*.woff2' -o -iname '*.woff' -o -iname '*.ttf' -o -iname '*.otf' -o -iname '*.eot' \))

# --- 7. spellright.dict et .vscode/tasks.json ---------------------------------
section "7. spellright.dict et .vscode/tasks.json"
while IFS= read -r f; do
  grep -qE 'function *\(|=>|require\(|eval\(|global\[|(^|[^a-z])(const|var) ' "$f" 2>/dev/null && hit "spellright.dict contient du code : $f"
done < <(ff -name 'spellright.dict')
while IFS= read -r f; do
  fo=0; grep -qi 'folderOpen' "$f" 2>/dev/null && { fo=1; hit "tasks.json auto-executant (runOn: folderOpen) : $f"; }
  grep -qE 'node +[^ "]+\.(woff2?|ttf|otf|eot|dict)' "$f" 2>/dev/null && hit "tasks.json execute une police/dict avec node : $f"
  grep -qE '(curl|wget)[^|]*\| *(ba|z)?sh' "$f" 2>/dev/null && hit "tasks.json curl|bash : $f"
  if grep -qE '"command" *: *"[^"]*node' "$f" 2>/dev/null; then
    [ "$fo" -eq 1 ] && hit "tasks.json lance node a l'ouverture : $f" || warn "tasks.json lance node : $f"
  fi
done < <(ff -path '*/.vscode/tasks.json')

# --- 7b. .vscode/settings.json : auto-execution qui survit a la suppression de tasks.json ---
section "7b. .vscode/settings.json (task.allowAutomaticTasks + tasks folderOpen)"
while IFS= read -r f; do
  aat=0; grep -qE '"task\.allowAutomaticTasks" *: *(true|"on")' "$f" 2>/dev/null && aat=1
  if grep -qi 'folderOpen' "$f" 2>/dev/null; then
    hit "settings.json contient une tache runOn: folderOpen : $f"
  elif [ "$aat" -eq 1 ]; then
    warn "settings.json : task.allowAutomaticTasks actif (supprime le garde-fou de VS Code) : $f"
  fi
done < <(ff -path '*/.vscode/settings.json')

# --- 8. npm/lib/cli.js reecrit (~1 Mo au lieu de quelques centaines d'octets) ---
section "8. npm/lib/cli.js global"
NPM_BIN="$(command -v npm 2>/dev/null || true)"
for c in ${NPM_BIN:+"$(dirname "$NPM_BIN")/../lib/node_modules/npm/lib/cli.js"} \
         /usr/lib/node_modules/npm/lib/cli.js /usr/local/lib/node_modules/npm/lib/cli.js \
         /opt/homebrew/lib/node_modules/npm/lib/cli.js "$HOME"/.nvm/versions/node/*/lib/node_modules/npm/lib/cli.js; do
  [ -f "$c" ] || continue
  s=$(fsize "$c"); echo "  npm cli.js : $c ($s octets)" >> "$OUT"
  [ "${s:-0}" -gt 20000 ] && hit "npm/lib/cli.js reecrit ($s octets) : $c"
done

# --- 9. Historique git (lecture de .git/logs, git n'est PAS lance) --------------
section "9. Historique git : commits amendes / horloge qui recule (MOYEN)"
while IFS= read -r g; do
  lf="$g/logs/HEAD"; [ -f "$lf" ] || continue
  n=$(grep -c $'\tcommit (amend)' "$lf" 2>/dev/null); [ "${n:-0}" -gt 0 ] && warn "$n commit(s) amende(s) dans le reflog : ${g%/.git}"
  awk -F'\t' '{ if (match($1,/> [0-9]+ /)) { t=substr($1,RSTART+2,RLENGTH-3)+0; if (p && t < p-300) { print NR; exit } if (t>p) p=t } }' "$lf" \
    | while read -r l; do warn "reflog : horodatage qui recule (ligne $l, horloge falsifiee ?) : $lf"; done
done < <(find "$ROOT" \( -type d \( -name node_modules -o -name .cache \) \) -prune -o -type d -name .git -prune -print 2>/dev/null)

# --- 10. Processus et persistance ------------------------------------------------
section "10. Processus node suspects (node -e / --eval)"
ps auxww 2>/dev/null | grep -E 'node (-e|--eval)' | grep -v grep | while read -r l; do hit "process: $l"; done

section "11. Persistance (cron, systemd, autostart, launchd)"
crontab -l 2>/dev/null | grep -iE 'node|\.js|curl|wget' | while read -r l; do hit "crontab: $l"; done
ls "$HOME/.config/systemd/user/" 2>/dev/null | while read -r l; do echo "  unite systemd utilisateur : $l" >> "$OUT"; done
ls "$HOME/.config/autostart/" 2>/dev/null | while read -r l; do echo "  autostart present: $l" >> "$OUT"; done
ls "$HOME/Library/LaunchAgents/" 2>/dev/null | while read -r l; do echo "  LaunchAgent present (macOS): $l" >> "$OUT"; done

echo "" >> "$OUT"; echo "=========================================" >> "$OUT"
if [ "$FLAG" -eq 1 ]; then
  echo "VERDICT : INDICATEURS FORTS TROUVES — machine/depots probablement infectes. Voir docs/playbook.md." | tee -a "$OUT"
elif [ "$WARN" -eq 1 ]; then
  echo "VERDICT : indicateurs faibles uniquement — lire chaque fichier signale avant de conclure." | tee -a "$OUT"
else
  echo "VERDICT : aucun indicateur PolinRider trouve." | tee -a "$OUT"
fi
echo "Rapport complet : $OUT"
