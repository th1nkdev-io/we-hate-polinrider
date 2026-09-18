# we-hate-polinrider

Boîte à outils et méthode pour **détecter, contenir et se remettre** d'une compromission par **PolinRider** — une campagne de supply-chain (attribuée à l'acteur nord-coréen Lazarus) qui vole identifiants, cookies de session et wallets, et se propage via GitHub en utilisant *tes* identifiants Git.

Tous les scripts sont **auditables** et, pour les détecteurs et l'audit serveur, **en lecture seule** : ils ne suppriment ni ne modifient rien. Lis le code avant de l'exécuter.

## ⚠️ Nouvelle variante : charge cachée par « bourrage d'espaces » dans les configs

Les premiers détecteurs cherchaient surtout ESLint et une ligne de ~32 000 caractères. Ils **rataient** la variante active en 2026. La charge est **ajoutée à la fin d'un fichier de config**, après ~280 espaces (invisible dans l'éditeur sans défilement horizontal). Elle s'exécute dès que l'outil **importe** ce fichier : `npm run dev`, `next build`, `eslint`, ou l'extension ESLint/Tailwind de l'IDE.

- **Cible n°1 : `postcss.config.mjs` (~62 %)**, puis `tailwind.config.*`, `eslint.config.*`/`.eslintrc.*`, `next.config.*`, `vite.config.*`, `webpack.config.*`, `astro`/`nuxt`/`svelte`/`rollup`/`babel`/`vue`/`gridsome`/`truffle`, et les fichiers d'entrée `App.js`/`index.js`. Liste complète : [`docs/indicators-of-compromise.md`](docs/indicators-of-compromise.md).
- Une config saine fait ~80–200 octets, une config infectée ~5 000.
- Les signatures ont **tourné** en juillet 2026 : `Cot%3t=shtP` et le décodeur `MDy` s'ajoutent à `rmcej%otb%` et `_$_1e42`.
- La détection se fait **par le contenu** (bourrage d'espaces, marqueurs, signatures binaires), jamais par le nom de fichier.

**Scan rapide d'un dossier de travail** (Python 3, Linux/macOS/Windows, lecture seule, aucun sous-processus) :
```bash
python3 detect/scan-workspace.py              # défaut : ~/_Workspace
python3 detect/scan-workspace.py ~/code --deep  # --deep : inclut aussi le contenu de .git/
```
Sortie `fichier:ligne` triée **HAUT / MOYEN**. Code de sortie : 2 = HAUT, 1 = MOYEN, 0 = rien.

> 🔑 **Si ESLint, PostCSS, Tailwind, Vite ou Next a tourné sur un dépôt infecté** (build, serveur de dev, extension de l'IDE), considère la charge comme **exécutée**. Fais tourner, depuis une machine saine : les **jetons GitHub** (PAT, OAuth/GitHub Apps, identifiants git en cache), les **jetons npm**, les **clés SSH**, les jetons CI/CD (Vercel, Netlify, Railway, Render), les clés cloud (AWS, GCP) et tous les secrets des `.env`. Voir l'étape 2 et l'étape 7 de [`docs/playbook.md`](docs/playbook.md).

> ⚠️ **N'exécute jamais un « nettoyeur PolinRider » tout fait téléchargé au hasard.** Les faux outils de remédiation sont un vecteur de second niveau typique de cette campagne. Ici, tout est lisible et sans binaire.

## Les 3 règles qui ne se négocient pas
1. **Ne jamais saisir un nouveau mot de passe sur une machine encore infectée** — le voleur le capture. Utilise un téléphone ou une machine saine.
2. **Ne jamais se reconnecter (SSH, `git push`) depuis une machine infectée** avant réinstallation — chaque connexion re-propage la charge.
3. **Se méfier des nettoyeurs tout faits** — n'exécute que des scripts dont tu as lu le code.

## Contenu

```
docs/
  playbook.md                       Procédure d'éradication complète en 8 étapes
  indicators-of-compromise.md       Liste exhaustive des IoC (détecter par le CONTENU, pas le nom)
detect/
  scan-workspace.py                 Scanner Python multiplateforme d'un dossier de projets (lecture seule)
  detect-polinrider-unix.sh         Détecteur Linux + macOS (lecture seule)
  detect-polinrider-windows.ps1     Détecteur Windows (lecture seule)
inventory/                          AVANT le wipe : savoir quoi faire tourner
  inventory-accounts-windows.ps1        Inventorie les comptes/identifiants du navigateur
  inventory-project-secrets-windows.ps1 Liste les noms de variables .env par projet
rescue/                             Sauver le travail non poussé, puis le restaurer
  triage-projects-windows.ps1           Trie les dépôts (propres / à vérifier)
  rescue-slim-windows.ps1               Crée des bundles légers du travail non poussé
  restore-rescue.py                     Rebranche ces bundles sur des clones frais
recover/                            Rebâtir sur la machine propre
  sync-repos.sh                         Reclone en masse tous tes dépôts depuis GitHub
server/
  audit-server.sh                       Audit de persistance d'un VPS (lecture seule)
```

## Ordre d'utilisation (résumé)

1. **Confiner** la machine infectée (fermer les IDE, couper le C2 — voir `docs/playbook.md`).
2. **Détecter** : `detect/scan-workspace.py` sur tes dossiers de projets, puis le script `detect/` adapté à l'OS (processus, persistance).
3. **Inventorier** (`inventory/`) ce qui a pu fuir, pour préparer la rotation des secrets.
4. **Sauver** le code non poussé (`rescue/`) — sans jamais l'ouvrir dans un IDE ni `npm install` avant nettoyage.
5. **Révoquer** depuis une machine SAINE, dans l'ordre : email → gestionnaire de mots de passe → GitHub → registrar/DNS → cloud → registries → paiements (voir le playbook).
6. **Réinstaller** la machine infectée, puis **durcir** : `npm config set ignore-scripts true`, VS Code `security.workspace.trust.enabled=true` et `task.allowAutomaticTasks=off`.
7. **Rebâtir** (`recover/sync-repos.sh`) puis **restaurer** le travail non poussé (`rescue/restore-rescue.py`).
8. **Auditer les serveurs** (`server/audit-server.sh`) et faire tourner tous leurs secrets.
9. **Surveiller** 30 jours (re-scan hebdo, revue du security log GitHub).

Le détail complet est dans **`docs/playbook.md`**.

## Durcissement à garder après coup
- `npm config set ignore-scripts true` (bloque les scripts postinstall malveillants).
- VS Code : `security.workspace.trust.enabled = true`, `task.allowAutomaticTasks = "off"`.
- Ne jamais ouvrir un dépôt non vérifié directement dans l'IDE.
- Nouvelle paire de clés SSH (ed25519), 2FA partout (clé FIDO2 de préférence), mots de passe uniques ≥ 20 caractères.

## Avertissement
Ces outils sont fournis tels quels, à but défensif et éducatif. Adapte-les à ton contexte et relis-les avant exécution. Aucune garantie.

## Licence
MIT — voir `LICENSE`.
