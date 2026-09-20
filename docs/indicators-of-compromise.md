# Indicateurs de compromission (IoC) — PolinRider

*Mis à jour : septembre 2026. Les indicateurs « tournent » (nouvelles signatures en juillet 2026) : revérifier régulièrement les sources en bas de page.*

**Règle d'or : détecter par le CONTENU, jamais par le nom de fichier.** L'attaquant contrôle les noms et les change. Un nom de fichier sert seulement à choisir quoi inspecter. Le verdict vient toujours de ce que le fichier contient : signature binaire, marqueurs, bourrage d'espaces.

Détecteurs fournis (lecture seule) :
- `detect/scan-workspace.py` : scanner multiplateforme d'un dossier de travail, avec résultats `fichier:ligne` triés HAUT/MOYEN et lecture du reflog git ;
- `detect/scan-git-history.py` : mêmes règles, mais sur **tous les commits de toutes les refs** (branches, `refs/pull/*` d'un clone `--mirror`) : un working tree propre ne prouve rien ;
- `detect/detect-polinrider-unix.sh` et `detect/detect-polinrider-windows.ps1` : scan de la machine, avec en plus les processus et la persistance ;
- `detect/triage-suspects.py` et `detect/inspect-repo-vectors.sh` : montrent la **preuve** (contenu tronqué et assaini) pour trancher entre infection et faux positif.

Le nettoyage du working tree est dans `clean/polinrider-clean.py` (simulation par défaut, quarantaine réversible).

Niveaux : **HAUT** = propre à la charge, considérer le dépôt/la machine comme compromis. **MOYEN** = parfois légitime, lire le fichier avant de conclure.

---

## 1. Fichiers de config ciblés : la variante « bourrage d'espaces »

La charge est **ajoutée à la fin** d'un fichier de configuration d'outil, après **~280 espaces** qui la rendent invisible sans défilement horizontal. Elle **s'exécute dès que l'outil importe le module** : un simple `npm run dev`, `next build`, `eslint .` ou l'extension ESLint/Tailwind de l'IDE suffit.

> 🎯 **`postcss.config.mjs` est la cible n°1 (~62 % des cas observés).** On ne le relit jamais, et il est chargé par Next.js, Vite et Tailwind à chaque build ou lancement du serveur de dev.

Fichiers ciblés (liste exhaustive connue) :

| Outil | Fichiers |
|---|---|
| PostCSS **(n°1)** | `postcss.config.mjs`, `postcss.config.js`, `postcss.config.ts`, `postcss.config.cjs` |
| Tailwind | `tailwind.config.js`, `.ts`, `.mjs`, `.cjs` |
| ESLint | `eslint.config.mjs`, `.js`, `.cjs`, `.eslintrc.js`, `.eslintrc.cjs` |
| Next.js | `next.config.mjs`, `.js`, `.ts` |
| Vite | `vite.config.js`, `.mjs`, `.ts`, `.cjs` |
| Webpack | `webpack.config.js`, `.mjs`, `.ts` |
| Astro / Nuxt | `astro.config.mjs`, `.js`, `.ts` · `nuxt.config.ts`, `.js`, `.mjs` |
| Autres | `svelte.config.js`, `rollup.config.js`, `babel.config.js`, `babel.config.cjs`, `gridsome.config.js`, `vue.config.js`, `truffle.js`, `truffle-config.js` |
| Fichiers d'entrée | `App.js`, `app.js`, `index.js` |

Heuristiques de contenu :
- **Bourrage en tête** : une ligne avec **≥ 100 espaces en tête** suivis de code. **HAUT** dans un fichier ciblé.
- **Bourrage au milieu** : `code … ≥ 30 espaces … code`. **HAUT** dans un fichier ciblé. Un commentaire aligné (`x; // …`) n'est pas signalé. En revanche, `/*x*/ code` est bien traité comme du code.
- **Ligne anormalement longue** : **≥ 1 000 caractères** dans un fichier de config (les premières variantes montaient à ~32 000). **HAUT**.
- **Taille** : une config saine fait **~80–200 octets**, une config infectée **~5 000 octets**. Au-delà de 3 000 octets : **MOYEN**, à relire.

> **Faux positif classique.** Un vide de 30 à 99 espaces n'est retenu que s'il est **suivi de code** : de l'ASCII art ou un alignement dans un commentaire n'est pas du bourrage. Le vrai bourrage fait des **centaines** d'espaces, donc ≥ 100 espaces + du code reste toujours suspect.

### Variante `global.i` (septembre 2026)

Même principe (charge collée à la fin d'une config), avec :
- un bourrage plus long, **~500 espaces** (et non ~280) ;
- la signature `global.i = 'A10-*40840'`, où **`A10-*40840` est un identifiant de campagne** ;
- puis du code obfusqué (`_0x1574`, …) qui se termine par `run();`.

Elle cible les mêmes fichiers, avec `eslint.config.*` très fréquent. Ne pas se fier au nombre exact d'espaces : chercher le contenu (`global.i`, `A10-`, `run();` après un vide).

Pour le voir soi-même sans rien exécuter :
```bash
grep -nE '^ {100,}[^ ]|[^ ] {30,}[^ ]|.{1000}' postcss.config.mjs | cut -c1-120   # n° de ligne + début
wc -c postcss.config.mjs
```

## 2. Marqueurs de la charge (HAUT)

Chercher dans **tous** les fichiers texte, pas seulement les `*.js` : la charge vit aussi dans des `.woff2`, des `.dict`, etc.

| Type | v1 (orig., mars 2026) | v2 (rotée, juillet 2026) |
|---|---|---|
| Signature | `rmcej%otb%` | `Cot%3t=shtP` |
| Fonction de décodage | `_$_1e42` | `MDy` (chercher `MDy(`) |
| Injection globale | `global['!']` (+ `global['r']`, `global['m']`) | `global['_V']='8-stN'` (tags `8-st1` … `8-st59`+) |
| Variante `global.i` (sept. 2026) | — | `global.i = 'A10-*40840'` puis `_0x…` … `run();` |
| Graines d'obfuscation (MOYEN) | `2857687`, `2667686` | `1111436`, `3896884` |

Clés XOR (déchiffrement de la charge) :
```
2[gWfGj;<:-93Z^C
m6:tTh^D)cBz?NM]
```

Adresses crypto servant de « boîte aux lettres » C2 (la charge suivante est lue dans les transactions) :
```
TRON   TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
TRON   TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
Aptos  0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e
Aptos  0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3
```

UUID du template piégé **StakingGame** (constant d'une victime à l'autre, dans `.vscode/tasks.json`) :
```
e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9
```

> ⚠️ Un fichier légitime qui **cite** ces marqueurs (article, ce dépôt, un autre outil de détection) déclenchera un faux positif. Les détecteurs ignorent leurs propres fichiers ; pour le reste, **lire le fichier** avant de conclure.
>
> **Gardes défensives.** Un `.github/workflows/security-guard.yml` (ou `security-guard.*`) qui contient ces signatures est en général une **garde légitime** : elle porte ce qu'elle traque. `scan-workspace.py` rétrograde ses marqueurs en **MOYEN** avec une note ; le nettoyeur n'y touche pas. Ne pas la supprimer d'office, mais la **lire** : un nom de fichier ne prouve rien.

## 3. Réseau / C2

**HAUT : endpoints Vercel** (vecteur « TasksJacker » via `tasks.json`). Motif d'URL : `https://<sous-domaine>.vercel.app/settings/(mac|linux|win)?flag=<N>`
```
default-configuration.vercel.app
260120.vercel.app
vscode-settings-bootstrap.vercel.app
vscode-settings-config.vercel.app
vscode-bootstrapper.vercel.app
vscode-load-config.vercel.app
```

**MOYEN : domaines blockchain** (C2 TRON en principal, Aptos en secours, BSC). Légitimes dans un projet web3 :
```
api.trongrid.io  trongrid.io
fullnode.mainnet.aptoslabs.com  aptoslabs.com
bsc-dataseed.binance.org  bsc-rpc.publicnode.com
```

**MOYEN : IP C2 connues** :
```
166.88.54.158   198.105.127.210  23.27.202.27   154.91.0.103
136.0.9.8       166.88.4.2       23.27.120.142  202.155.8.173
166.88.134.82   188.43.33.249    23.27.13.43
```

**MOYEN : exfiltration Telegram** (variantes récentes) : `api.telegram.org` dans un fichier de config ou d'entrée.

À bloquer : domaines en `0.0.0.0` dans `hosts` et au pare-feu, IP au pare-feu (entrée et sortie).

## 4. Paquets npm piégés (typosquats de `tailwindcss-animate` & co.)

À chercher dans `package.json` **et** dans les lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`), ainsi que dans `node_modules/` :

| Paquet | Version observée |
|---|---|
| `tailwindcss-style-animate` | 1.1.6 (dépendance du faux test technique **ShoeVista**, dans `client/package.json`) |
| `tailwind-mainanimation` | 2.3.3 |
| `tailwind-autoanimation` | 2.3.6 |
| `tailwind-animationbased` | — |
| `tailwindcss-typography-style` | 0.8.2 |
| `tailwindcss-style-modify` | 0.8.3 |
| `tailwindcss-animate-style` | 1.2.5 |

Éditeurs npm connus (comptes supprimés) : `allavin`, `blackedward`. Le paquet légitime `tailwindcss-animate` n'est **pas** concerné : les détecteurs vérifient le nom exact.

## 5. Fichiers IoC et leurres

- `temp_auto_push.bat` : propagation, fiabilité **~100 %** (101 dépôts, 0 faux positif). Il contient les variables `LAST_COMMIT_DATE`, `LAST_COMMIT_TIME`, `LAST_COMMIT_TEXT`, `USER_NAME`, `USER_EMAIL`, `CURRENT_BRANCH`.
- `config.bat` : autre artefact de propagation. Nom générique : juger sur le contenu (`git commit --amend`, `LAST_COMMIT_DATE`).
- `branch_structure.json` : déposé par la charge.
- **Fausses polices** `.woff2`, `.woff`, `.ttf`, `.otf`, `.eot` (souvent `public/fonts/fa-solid-400.woff2`, `fa-solid-500.woff2`, …) : des centaines d'espaces puis du JavaScript, ~32 Ko.
  **Détecter par la signature binaire (magic bytes), jamais par le nom** :

  | Format | Premiers octets |
  |---|---|
  | WOFF2 | `wOF2` |
  | WOFF | `wOFF` |
  | TrueType | `00 01 00 00` ou `true` |
  | OpenType CFF | `OTTO` |
  | Collection | `ttcf` |
  | EOT | pas de magic en tête : `4C 50` à l'offset 34 |

- `spellright.dict` (dictionnaire de l'extension VS Code Spell Right) **contenant du code** (chargeur).
- `.vscode/tasks.json` :
  - `"runOn": "folderOpen"` : exécution automatique à l'ouverture du dossier. **HAUT** ;
  - `"command"` qui lance `node` (HAUT si combiné à `folderOpen`, MOYEN seul), en particulier sur une police : `node ./public/fonts/fa-solid-400.woff2` ;
  - `curl … | bash` vers un endpoint Vercel ci-dessus ;
  - l'UUID StakingGame `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9`.
- `.vscode/settings.json` : **relance la charge même si `tasks.json` a été supprimé**. Deux clés à chercher :
  - `"task.allowAutomaticTasks": true` (supprime le garde-fou de VS Code) : **MOYEN** seule ;
  - un bloc `"tasks"` avec `"runOn": "folderOpen"` (souvent avec `terminal.integrated.hideOnStartup`) : **HAUT**.
- **`npm/lib/cli.js` réécrit** : le fichier légitime fait quelques centaines d'octets sur 4 lignes. Le fichier piégé fait **~1 Mo**, avec la charge ajoutée après du blanc à partir de la ligne 5. Chaque appel à `npm` relance alors la charge.
- Antivirus : Microsoft Defender détecte `Trojan:JS/PolinRider.DB!MTB`.

## 6. Historique Git

- Commits **réécrits** par `git commit --amend --no-verify` puis `git push -uf`, en **gardant la date et le message d'origine**. Le script règle l'horloge système sur la date d'origine avant d'amender.
- Traces locales : `git reflog` montre des entrées `commit (amend)` que tu n'as pas faites. Dans `.git/logs/HEAD`, les **horodatages reculent** (horloge falsifiée).
- Traces GitHub : « *[user] force pushed the branch* » dans l'activité, commits **Unverified** alors que tu signes d'habitude.
- `pull` ou déploiements CI inattendus apparaissant du jour au lendemain sur tous les dépôts.

**Un working tree propre ne prouve rien.** Un commit « remove virus » retire souvent le déclencheur (`tasks.json`) mais laisse le **payload** (fausse police, config) dans un commit ancien, une autre branche ou `refs/pull/*`. Et GitHub sert les anciens commits par SHA même après un force-push. Toujours analyser **tous les commits de toutes les refs** :
```bash
git clone --mirror <url> depot.git          # dans un dossier de travail jetable, jamais dans le clone
python3 detect/scan-git-history.py depot.git
```
Le *security log* de compte GitHub **ne trace pas les `git push` individuels** : « compte non compromis » ne veut pas dire « dépôts non infectés ».

Vérification manuelle (lecture seule) :
```bash
git reflog --date=iso | grep -i amend
git log --format='%h %ad %cd %an %s' --date=iso | head -50   # author date ≠ committer date ?
```

## 7. Sur un serveur

- Clé SSH inconnue dans un `authorized_keys` (comparer les empreintes).
- Compte/sudo, cron, unité systemd, `.bashrc`/`.profile` récemment ajoutés.
- Processus `node -e` / `node --eval` détachés.
- Connexions SSH acceptées depuis des IP/clés que tu ne reconnais pas, ou vers les IP C2 ci-dessus.

---
*Sources : [OpenSourceMalware/PolinRider (README)](https://github.com/OpenSourceMalware/PolinRider/blob/main/README.md), [Developer guide: getting over PolinRider](https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider), analyses Socket.dev, Wiz, The Hacker News, et un incident de première main. Indicateurs vérifiés contre ces sources en septembre 2026.*
