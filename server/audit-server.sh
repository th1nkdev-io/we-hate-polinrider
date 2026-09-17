#!/usr/bin/env bash
# audit-server.sh — audit de persistance LECTURE SEULE d'un serveur Linux / VPS
# potentiellement touché par PolinRider (ou une intrusion générique).
# Ne supprime/modifie RIEN. À lancer en root, de préférence via la console du
# fournisseur (KVM/rescue), PAS par SSH si un accès a pu être piégé.
#
#   sudo bash audit-server.sh
#
# On LIT, on analyse, PUIS on décide (nettoyer vs réinstaller). Ne rien effacer
# avant d'avoir conclu : les logs sont la preuve.
set +H 2>/dev/null || true

# Empreinte(s) de clé SSH connue(s) comme malveillante(s) — à adapter à ton incident.
BAD_KEYS=("SHA256:WNgFcLO4fHGLRnDq5WwkqpuAed6qjAy1VmUsGdhtmNA")

line(){ printf '\n===== %s =====\n' "$1"; }

line "UTILISATEURS avec shell"
grep -vE '/(nologin|false)$' /etc/passwd

line "DROITS SUDO"
getent group sudo
grep -rhE '^[^#].*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null

line "CLES SSH autorisées (chercher les inconnues)"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && echo "--- $f ---" && cat "$f"
done

line "CRON (tous utilisateurs + system)"
for u in $(cut -d: -f1 /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "--- $u ---" && echo "$c"
done
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d /etc/cron.*/ 2>/dev/null

line "SERVICES systemd récents"
ls -lt /etc/systemd/system/*.service 2>/dev/null | head

line "PROCESSUS suspects (node -e, /tmp, /dev/shm, curl/wget)"
ps aux | grep -iE 'node .*(-e|--eval)|/tmp/|/dev/shm|curl|wget' | grep -v grep

line "FICHIERS dans /tmp /var/tmp /dev/shm"
ls -la /tmp /var/tmp /dev/shm 2>/dev/null

line "PORTS EN ÉCOUTE"
ss -tulpn 2>/dev/null | grep -i listen

line "CONNEXIONS SORTANTES établies (chercher C2 / IP inconnues)"
ss -tunp state established 2>/dev/null | head -40

line "MARQUEURS du payload dans le code déployé"
grep -rlE "rmcej%otb%|Cot%3t=shtP|_\$_1e42|global\['_V'\]|global\['!'\]|branch_structure" \
  /home /var/www /srv /opt 2>/dev/null \
  --include='*.js' --include='*.mjs' --include='*.ts' --include='*.cjs' | head
# NB : un article/détecteur qui CITE ces marqueurs est un faux positif — lire le fichier avant de conclure.

line "FICHIERS IoC"
find /home /var/www /srv /opt \
  \( -name 'tasks.json' -o -name 'temp_auto_push.bat' -o -name 'branch_structure.json' \) 2>/dev/null

line "DERNIÈRES CONNEXIONS (root étranger ?)"
last -a -n 25 2>/dev/null
echo "--- clés acceptées dans auth.log ---"
grep -iE 'Accepted publickey' /var/log/auth.log 2>/dev/null | tail -25
echo ""
echo "--- présence des empreintes malveillantes connues ---"
for k in "${BAD_KEYS[@]}"; do
  if grep -q "$k" /var/log/auth.log* 2>/dev/null; then
    echo "  [!] EMPREINTE MALVEILLANTE UTILISÉE : $k"
    grep "$k" /var/log/auth.log* 2>/dev/null | tail -10
  else
    echo "  [ok] pas de trace de $k"
  fi
done

printf '\n===== FIN — analyser avant de supprimer quoi que ce soit =====\n'
