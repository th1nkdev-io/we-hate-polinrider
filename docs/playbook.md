# Playbook — Éradication complète de PolinRider

**Objet :** procédure ordonnée pour nettoyer une compromission PolinRider de bout en bout : comptes, code, machines, serveurs. À partager avec les collaborateurs.
**Principe directeur :** on coupe les accès depuis une machine SAINE, on éradique sur les machines infectées, on fait tourner tous les secrets, puis on restaure. **Jamais l'inverse.**

> PolinRider est une campagne de supply-chain attribuée à un acteur nord-coréen (Lazarus). Elle vole les identifiants, cookies de session et wallets, et se propage via GitHub en utilisant *vos* identifiants Git. Un simple nettoyage ne suffit pas : le malware se ré-injecte. Traitez toute machine touchée comme entièrement compromise.

---

## Les 3 règles qui ne se négocient pas

1. **Ne jamais saisir un nouveau mot de passe sur une machine encore infectée.** Le voleur le capture. → utilisez un téléphone ou une machine saine.
2. **Ne jamais se reconnecter (SSH, git push) depuis une machine infectée** avant qu'elle soit réinstallée. Chaque connexion re-propage la charge.
3. **Se méfier des « nettoyeurs PolinRider » tout faits.** Les faux outils de remédiation sont un vecteur de second niveau. N'exécutez que des scripts dont vous avez lu le code.

---

## Étape 0 — Confinement immédiat (chaque machine potentiellement infectée)

- [ ] Fermer VS Code, Cursor, tout IDE (le payload s'exécute tant que l'IDE tourne).
- [ ] Tuer les processus `node -e` / `node --eval` détachés.
- [ ] Couper le canal C2 : ajouter aux `hosts` (bloque en `0.0.0.0`) : `api.trongrid.io`, `trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `aptoslabs.com`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com`, `default-configuration.vercel.app`, `260120.vercel.app`, `vscode-settings-bootstrap.vercel.app`, `vscode-settings-config.vercel.app`, `vscode-bootstrapper.vercel.app`, `vscode-load-config.vercel.app`.
- [ ] Débrancher les wallets matériels et clés physiques.
- [ ] Se procurer une **machine ou un téléphone sain** pour les étapes 1 à 3.

## Étape 1 — Détection (sur chaque machine)

Lancer le détecteur adapté (scripts fournis, lecture seule) :
- Windows : `detect-polinrider-windows.ps1`
- Linux / macOS : `detect-polinrider-unix.sh`
- Dossiers de projets (tout OS) : `python3 detect/scan-workspace.py <dossier>` (`fichier:ligne`, HAUT/MOYEN)

Indicateurs (du plus fiable au moins) : `temp_auto_push.bat` · `branch_structure.json` · `.vscode/tasks.json` avec `runOn: folderOpen` · **fichier de police** (`.woff2`, `.woff`, `.ttf`, `.otf`, `.eot`) dont le **contenu** n'est pas une vraie police (détecter par la signature binaire, PAS par le nom — le nom varie : `fa-solid-400`, `fa-solid-500`, etc.) · **charge ajoutée à la fin d'une config après un bourrage d'espaces** (cible n°1 `postcss.config.mjs`, puis `tailwind`/`eslint`/`next`/`vite`/`webpack.config.*`…) ou ligne ≥ 1 000 caractères · marqueurs `rmcej%otb%`, `Cot%3t=shtP`, `_$_1e42`, `MDy(`, `global['_V']`, `global['!']`, clés XOR, adresses TRON/Aptos · paquets npm `tailwindcss-style-animate` & co. (y compris dans les lockfiles) · C2 `*.vercel.app` · `npm/lib/cli.js` de ~1 Mo. Liste complète : `docs/indicators-of-compromise.md`. · commits force-push réécrits gardant date/message d'origine.

> **Note détection police :** ne jamais filtrer sur le nom du fichier — l'attaquant le change (aujourd'hui `fa-solid-500.woff2`, hier `fa-solid-400.woff2`). Vérifier la signature binaire de *chaque* fichier de police, et signaler tout fichier de police contenant du JavaScript.

> Une machine avec ≥1 indicateur = **à réinstaller** (voir étape 5). Ne pas se contenter de « nettoyer ».

## Étape 2 — Révocation d'urgence (depuis la machine SAINE, dans cet ordre)

L'ordre compte : l'email est la racine de récupération de tout le reste.

1. **Email principal** (+ tout email de récupération) : nouveau mot de passe → *déconnecter toutes les sessions* → vérifier règles de transfert, alias, méthodes 2FA, emails/téléphones de récupération (supprimer les inconnus) → régénérer les codes de secours → couper POP/IMAP si inutilisé.
2. **Gestionnaire de mots de passe** : mot de passe maître + révoquer les appareils + considérer tout le coffre à faire tourner.
3. **GitHub / GitLab** : changer le mot de passe → révoquer **tous** les PAT (classic + fine-grained), toutes les clés SSH/GPG, toutes les OAuth/GitHub Apps, toutes les sessions → vérifier emails du compte, 2FA, deploy keys, webhooks, Actions secrets, collaborateurs → **exporter le security log** (preuve + périmètre).
4. **Registrar / DNS** (Namecheap, GoDaddy, IONOS, Cloudflare, Freenom) : mot de passe, tokens API, vérifier les enregistrements DNS, activer le registrar lock.
5. **Fournisseurs cloud / VPS** (AWS, Hetzner, OVH, DO, Hostinger…) : mot de passe, révoquer toutes les clés API, vérifier VM/snapshots/pare-feu créés.
6. **Registries de paquets** (npm, PyPI, Packagist, Docker Hub) : révoquer les tokens, 2FA de publication, vérifier qu'aucune version n'a été publiée sous votre nom.
7. **Paiements & banque** (Stripe, PayPal, banques, passerelles) : mot de passe, révoquer les clés API live+test, vérifier bénéficiaires et transactions.
8. **Wallets crypto** : nouveau wallet, nouvelle seed, transférer les fonds. Toute ancienne seed est brûlée.

## Étape 3 — Notifier (sans délai)

- [ ] Prévenir les collaborateurs et clients dont un accès, un dépôt ou un serveur a pu être touché.
- [ ] Si des **données personnelles** sont concernées : évaluer l'obligation RGPD (notification sous 72 h). Le sous-traitant prévient le responsable de traitement sans délai.
- [ ] Message factuel : ce qui s'est passé, période concernée, ce que le destinataire doit vérifier/révoquer de son côté.

## Étape 4 — Serveurs / VPS (depuis la machine saine, nouvelle clé SSH)

Serveur par serveur, production d'abord. Accès via la **console du fournisseur** (KVM/rescue) plutôt que SSH quand c'est possible.

- [ ] Lister toutes les clés `authorized_keys` (tous utilisateurs) et supprimer les inconnues.
- [ ] Lister les comptes connectables + les droits sudo ; supprimer les inconnus.
- [ ] Chercher la persistance : `cron` (tous users), unités `systemd` récentes, `.bashrc`/`.profile`, `/etc/profile.d`, processus `node -e`, fichiers récents dans `/tmp`, `/var/tmp`, `/dev/shm`.
- [ ] Chercher le C2 et le payload dans `/var/www /opt /srv /home` (mêmes motifs qu'en étape 1) + faux `.woff2`.
- [ ] **Décision** : IoC trouvé, clé/compte inconnu, ou données clients → **réinstallation complète**. Sinon nettoyage + surveillance.
- [ ] Faire tourner **tous** les secrets serveur : mots de passe DB, `.env` (clés API, secrets JWT/session, webhooks), certificats/clés TLS stockés, clés de déploiement, identifiants SMTP. Changer le secret de session invalide toutes les sessions applicatives.
- [ ] Bloquer les domaines C2 au pare-feu ; surveiller les logs SSH.

## Étape 5 — Machines infectées : réinstallation

1. **Avant le wipe** (hors ligne) : relever les traces (extensions IDE, tâches planifiées, historique shell), copier **uniquement des données inertes** (documents, images, dumps SQL) sur un support neuf, extraire la **liste des services** mentionnés dans les notes/`.env` pour la rotation. Jamais : exécutables, `node_modules`, profils navigateur, `.ssh`, `.npmrc`, config à secrets.
2. **Sauver le code non poussé** : copier les dépôts **sans `node_modules`** (mais avec le `.git`) sur clé USB → scanner/nettoyer sur une machine saine → **jamais** ouvrir dans un IDE ni `npm install` avant nettoyage.
3. **Réinstaller le système** (formatage complet).
4. **Durcir** avant de reprendre : `security.workspace.trust.enabled=true`, `task.allowAutomaticTasks=off`, `npm config set ignore-scripts true`, extensions IDE en installation manuelle, ne jamais ouvrir un dépôt non vérifié directement dans l'IDE.

## Étape 6 — Dépôts Git

- [ ] Cloner en miroir tous les dépôts et scanner (mêmes IoC) **avant** de les ouvrir.
- [ ] Nettoyer les fichiers injectés (`tasks.json`, faux `.woff2`, `branch_structure.json`, config avec charge après bourrage d'espaces ou ligne géante, `spellright.dict`), régénérer les lockfiles.
- [ ] Force-push la correction → réactiver la protection de branche → exiger les **commits signés**.
- [ ] Faire tourner tous les secrets présents dans les builds CI de chaque dépôt.
- [ ] Ajouter un scan IoC dans la CI. **Re-scanner chaque semaine pendant 1 mois** (la ré-infection est documentée).

## Étape 7 — Rotation complète des secrets

Tableau de suivi : service | type de secret | date rotation | fait par | vérifié.
Ordre : email → gestionnaire → GitHub → registrar/DNS → cloud → registries → paiements → bases de données → applications → le reste.
Règles : mots de passe uniques ≥20 car. ; **nouvelle** paire de clés SSH (ed25519) ; 2FA partout (clé FIDO2 de préférence) ; codes de secours hors ligne ; « déconnecter toutes les sessions » à chaque fois.

## Étape 8 — Surveillance (30 jours)

- [ ] Re-scan hebdomadaire des dépôts + scan CI sur chaque PR.
- [ ] Revue hebdomadaire du security log GitHub.
- [ ] Alertes de connexion activées (email, GitHub, cloud).
- [ ] Domaines C2 bloqués au pare-feu sur tous les serveurs.
- [ ] Vérifier qu'aucune publication n'apparaît sous vos comptes de registries.

---

## Ordre de priorité si le temps manque
Confinement (0) → email + gestionnaire + GitHub (2.1–2.3) → notifier (3) → serveurs de production (4) → le reste.

## Interdépendances (à ne pas inverser)
- Machine saine **avant** toute révocation (étape 2).
- Révocation GitHub **avant** de recloner/pousser (étape 6).
- Sauvetage + scan du code **avant** réinstallation (étape 5).
- Réinstallation **avant** de reprendre le travail sur la machine.
- Rotation des secrets serveur **après** avoir repris le contrôle des accès (étape 4).

*IoC et procédure basés sur les analyses OpenSourceMalware/PolinRider, Socket.dev, Wiz, The Hacker News, et un rapport d'incident client de première main.*
