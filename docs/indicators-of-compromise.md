# Indicateurs de compromission (IoC) — PolinRider

Du plus fiable au moins fiable. **Règle d'or : détecter par le CONTENU, pas par le nom de fichier** — l'attaquant contrôle les noms, il les change.

## Fichiers
- `temp_auto_push.bat` — fiabilité ~100 %.
- `branch_structure.json` — déposé par la charge.
- `.vscode/tasks.json` contenant `runOn: folderOpen` — exécution automatique à l'ouverture du dossier dans l'IDE.

## Fausses polices (le vecteur emblématique)
Un fichier de police (`.woff2`, `.woff`, `.ttf`, `.otf`, `.eot`) dont le **contenu n'est pas une vraie police**.
- Une vraie police WOFF2 commence par la signature binaire `wOF2`.
- La fausse commence par des centaines d'espaces, puis du JavaScript.
- **Détecter par la signature binaire (magic bytes), JAMAIS par le nom** : le nom varie (`fa-solid-400.woff2`, `fa-solid-500.woff2`, …).
- Taille typique du leurre observée : ~32 Ko.

## Marqueurs dans le code
Chaînes présentes dans la charge (chercher dans `*.js`, `*.mjs`, `*.cjs`, `*.ts`) :
```
rmcej%otb%
Cot%3t=shtP
_$_1e42
global['_V']
global['!']
```
- Une **ligne d'environ 32 000 caractères** dans un fichier `*.config.*` (ex. `vite.config.js`).

> ⚠️ Un fichier légitime (article, script de détection) qui **cite** ces marqueurs déclenchera un faux positif. Toujours **lire le fichier** avant de conclure.

## Paquets npm malveillants observés
`tailwindcss-style-animate`, `tailwind-mainanimation`, et variantes. Vérifier les `dependencies` inhabituelles et les lockfiles.

## Comportement Git
- Commits **force-push réécrits** conservant la date et le message d'origine.
- `pull` ou déploiements CI **inattendus** apparaissant du jour au lendemain sur tous les dépôts.

## Réseau (canaux C2 à bloquer)
Domaines à mettre en `0.0.0.0` dans `hosts` et à bloquer au pare-feu :
```
api.trongrid.io  trongrid.io
fullnode.mainnet.aptoslabs.com  aptoslabs.com
bsc-dataseed.binance.org  bsc-rpc.publicnode.com
default-configuration.vercel.app  260120.vercel.app
vscode-settings-bootstrap.vercel.app  vscode-settings-config.vercel.app
vscode-bootstrapper.vercel.app  vscode-load-config.vercel.app
```

## Sur un serveur
- Clé SSH inconnue dans un `authorized_keys` (comparer les empreintes).
- Compte/sudo, cron, unité systemd, `.bashrc`/`.profile` récemment ajoutés.
- Processus `node -e` / `node --eval` détachés.
- Connexions SSH acceptées depuis des IP/clés que tu ne reconnais pas.

---
*Basé sur les analyses publiques OpenSourceMalware/PolinRider, Socket.dev, Wiz, The Hacker News, et un incident de première main.*
