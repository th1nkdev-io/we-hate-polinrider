#!/usr/bin/env bash
# detect-polinrider-unix.sh
# Detecteur PolinRider pour Linux ET macOS — LECTURE SEULE (ne supprime/modifie rien).
# Usage :
#     chmod +x detect-polinrider-unix.sh
#     ./detect-polinrider-unix.sh            # scanne $HOME
#     ./detect-polinrider-unix.sh /chemin    # scanne un dossier precis
# Resultat : rapport ~/detect-polinrider.txt + verdict a l'ecran.
# Script auditable : lisez-le avant de l'executer.
set -uo pipefail
ROOT="${1:-$HOME}"
OUT="$HOME/detect-polinrider.txt"
FLAG=0
: > "$OUT"
echo "### DETECTION POLINRIDER — $(date) — $(hostname) — cible: $ROOT" >> "$OUT"
# exclusions communes
PRUNE=( -path '*/node_modules' -o -path '*/.cache' -o -path '*/Library/Caches' )
hit(){ FLAG=1; echo "  [!] $1" | tee -a "$OUT"; }

echo "" >> "$OUT"; echo "== 1. temp_auto_push.bat (fiabilite 100%) ==" >> "$OUT"
while IFS= read -r f; do hit "temp_auto_push.bat : $f"; done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o -name 'temp_auto_push.bat' -print 2>/dev/null)

echo "" >> "$OUT"; echo "== 2. branch_structure.json (IoC confirme) ==" >> "$OUT"
while IFS= read -r f; do hit "branch_structure.json : $f"; done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o -name 'branch_structure.json' -print 2>/dev/null)

echo "" >> "$OUT"; echo "== 3. .vscode/tasks.json auto-executant (folderOpen) ==" >> "$OUT"
while IFS= read -r f; do
  grep -q 'folderOpen' "$f" 2>/dev/null && hit "tasks.json folderOpen : $f"
done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o -path '*/.vscode/tasks.json' -print 2>/dev/null)

echo "" >> "$OUT"; echo "== 4. Marqueurs du payload dans le code ==" >> "$OUT"
while IFS= read -r f; do hit "marqueur payload : $f"; done < <(
  grep -rlF --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
    -e 'rmcej%otb%' -e 'Cot%3t=shtP' -e '_$_1e42' -e "global['_V']" -e "global['!']" \
    "$ROOT" 2>/dev/null | grep -v node_modules)

echo "" >> "$OUT"; echo "== 5. Faux .woff2 (JavaScript deguise) ==" >> "$OUT"
while IFS= read -r f; do
  sig=$(head -c4 "$f" 2>/dev/null)
  [ "$sig" != "wOF2" ] && hit "faux .woff2 : $f"
done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o -name '*.woff2' -print 2>/dev/null)

echo "" >> "$OUT"; echo "== 6. Ligne geante dans un fichier de config (~32000 car.) ==" >> "$OUT"
while IFS= read -r f; do
  awk 'length>5000{print FILENAME" : ligne "NR" = "length" caracteres"; exit}' "$f" 2>/dev/null | while read -r l; do hit "$l"; done
done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o \( -name 'vite.config.*' -o -name 'postcss.config.*' -o -name 'tailwind.config.*' -o -name 'next.config.*' -o -name 'webpack.config.*' -o -name '*.config.js' -o -name '*.config.mjs' \) -print 2>/dev/null)

echo "" >> "$OUT"; echo "== 7. Paquets npm malveillants ==" >> "$OUT"
while IFS= read -r f; do hit "paquet malveillant : $f"; done < <(
  grep -rlE 'tailwindcss-style-animate|tailwind-mainanimation|tailwind-autoanimation|tailwindcss-typography-style|tailwindcss-style-modify' \
    "$ROOT" --include='package*.json' 2>/dev/null | grep -v node_modules)

echo "" >> "$OUT"; echo "== 8. Traces C2 ==" >> "$OUT"
while IFS= read -r f; do hit "trace C2 : $f"; done < <(
  grep -rlE 'trongrid\.io|aptoslabs\.com|bsc-dataseed|vscode-bootstrapper|default-configuration\.vercel' \
    "$ROOT" --include='*.js' --include='*.mjs' --include='*.json' 2>/dev/null | grep -v node_modules)

echo "" >> "$OUT"; echo "== 9. Processus node suspects (node -e / --eval) ==" >> "$OUT"
ps auxww 2>/dev/null | grep -E 'node (-e|--eval)' | grep -v grep | while read -r l; do hit "process: $l"; done

echo "" >> "$OUT"; echo "== 10. Persistance (cron, systemd, autostart, launchd) ==" >> "$OUT"
crontab -l 2>/dev/null | grep -iE 'node|\.js|curl|wget' | while read -r l; do hit "crontab: $l"; done
ls "$HOME/.config/autostart/" 2>/dev/null | while read -r l; do echo "  autostart present: $l" >> "$OUT"; done
ls "$HOME/Library/LaunchAgents/" 2>/dev/null | while read -r l; do echo "  LaunchAgent present (macOS): $l" >> "$OUT"; done

echo "" >> "$OUT"; echo "=========================================" >> "$OUT"
if [ "$FLAG" -eq 1 ]; then
  echo "VERDICT : INDICATEURS TROUVES — machine probablement infectee." | tee -a "$OUT"
else
  echo "VERDICT : aucun indicateur PolinRider trouve." | tee -a "$OUT"
fi
echo "Rapport complet : $OUT"
