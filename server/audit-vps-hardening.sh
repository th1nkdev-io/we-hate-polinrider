#!/usr/bin/env bash
# audit-vps-hardening.sh — état de sécurité du VPS (LECTURE SEULE).
# À lancer SUR le VPS, avec un utilisateur qui a sudo :
#   scp audit-vps-hardening.sh user@vps:~   puis   ssh user@vps 'bash ~/audit-vps-hardening.sh'
# Ne modifie/installe rien. Rapporte seulement la posture pour décider du durcissement.
set -uo pipefail
S() { echo; echo "══════ $* ══════"; }

S "1. Système & mises à jour"
. /etc/os-release 2>/dev/null && echo "OS : $PRETTY_NAME"
echo "Noyau : $(uname -r)"
if command -v apt >/dev/null; then
  echo "Paquets à mettre à jour : $(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  echo -n "Mises à jour auto (unattended-upgrades) : "
  dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii' && echo "installé" || echo "ABSENT"
fi

S "2. Configuration SSH effective"
if command -v sshd >/dev/null; then
  sudo sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|challengeresponseauthentication|allowusers|allowgroups|x11forwarding)\b' \
    || grep -Ei '^\s*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
else
  echo "sshd non trouvé"
fi

S "3. Clés SSH autorisées (tous comptes)"
sudo find /home /root -name authorized_keys -exec sh -c 'echo "--- $1"; cat "$1"' _ {} \; 2>/dev/null || echo "(aucune)"

S "4. Comptes pouvant se connecter + sudo"
awk -F: '$7 !~ /(nologin|false|sync)$/ {print "  login: "$1"  uid="$3"  shell="$7}' /etc/passwd
echo "-- sudoers --"
sudo grep -rhE '^[^#]*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/  /'

S "5. Pare-feu"
if command -v ufw >/dev/null; then echo "ufw :"; sudo ufw status verbose 2>/dev/null | sed 's/^/  /'
elif command -v nft >/dev/null && sudo nft list ruleset 2>/dev/null | grep -q .; then
  echo "nftables : règles présentes"; sudo nft list ruleset 2>/dev/null | head -30 | sed 's/^/  /'
else
  echo "iptables :"; sudo iptables -S 2>/dev/null | sed 's/^/  /' | head -30
fi

S "6. fail2ban"
if command -v fail2ban-client >/dev/null; then
  echo "installé — jails :"; sudo fail2ban-client status 2>/dev/null | sed 's/^/  /'
else echo "ABSENT (pas de protection anti-bruteforce SSH)"; fi

S "7. Ports en écoute (exposés)"
sudo ss -tulnp 2>/dev/null | awk 'NR==1 || /LISTEN/' | sed 's/^/  /'
echo "  → un port sur 0.0.0.0/:: = exposé à Internet ; sur 127.0.0.1 = local seulement"

S "8. Docker"
if command -v docker >/dev/null; then
  echo "Conteneurs et ports publiés :"
  sudo docker ps --format '  {{.Names}}  [{{.Image}}]  ports={{.Ports}}' 2>/dev/null
  echo -n "Socket docker exposé en TCP ? "
  sudo ss -tulnp 2>/dev/null | grep -q ':2375' && echo "OUI (DANGER)" || echo "non"
  echo -n "Conteneurs tournant en root : "
  for c in $(sudo docker ps -q 2>/dev/null); do
    u=$(sudo docker inspect -f '{{.Config.User}}' "$c" 2>/dev/null); [ -z "$u" ] && echo -n "$(sudo docker inspect -f '{{.Name}}' "$c" 2>/dev/null | tr -d /) "; done; echo
else echo "Docker non installé"; fi

S "9. Fichiers .env (secrets à faire tourner)"
sudo find /opt /srv /var/www /home -maxdepth 4 -name '.env' -not -path '*/node_modules/*' 2>/dev/null | sed 's/^/  /' | head -30
echo "  (contenu NON affiché — on les traitera un par un)"

S "10. Connexions SSH récentes"
echo "-- réussies (10 dernières) --"; last -a 2>/dev/null | head -10 | sed 's/^/  /'
echo "-- échouées (bruteforce ?) --"; sudo lastb -a 2>/dev/null | head -5 | sed 's/^/  /' || echo "  (indisponible)"

S "11. Tâches planifiées (cron)"
for u in $(cut -f1 -d: /etc/passwd); do cr=$(sudo crontab -u "$u" -l 2>/dev/null); [ -n "$cr" ] && echo "  [$u] $cr"; done
sudo ls -1 /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | sed 's/^/  /'

echo; echo "══════ FIN ══════"
