# Prompt — Nettoyer un dépôt Git infecté (avec Claude Code)

Ce document contient un **prompt prêt à coller** dans [Claude Code](https://claude.com/claude-code) pour nettoyer **un dépôt** infecté par PolinRider : détection sur tout l'historique, réécriture, publication dans un dépôt neuf et remise à niveau du clone local, avec une confirmation obligatoire avant toute action visible à l'extérieur.

Il complète l'étape 6 du [`playbook.md`](playbook.md) (« Dépôts Git ») et s'appuie sur la liste de [`indicators-of-compromise.md`](indicators-of-compromise.md).

## Pourquoi un dépôt neuf et pas un force-push ?

- Après un force-push, GitHub garde les anciens commits **accessibles par leur SHA** (et via le cache des forks/PR).
- Les refs `refs/pull/*` ne peuvent **pas** être supprimées : elles gardent le payload.
- Seul un **nouveau dépôt**, alimenté par les branches nettoyées, garantit que le payload n'est plus servi par GitHub.

## Avant de lancer

- Lance Claude Code **dans le clone concerné**, mais **n'ouvre pas ce dossier dans VS Code** tant qu'il n'est pas nettoyé (la tâche `folderOpen` s'exécuterait).
- Prérequis : `git`, [`git filter-repo`](https://github.com/newren/git-filter-repo), `gh` authentifié (`gh auth status`).
- Fais-le depuis une machine **saine**. Sur une machine déjà infectée, applique d'abord l'étape 0 du playbook.
- Le prompt interdit à Claude de saisir un secret ou de rien modifier sur GitHub sans ton accord : garde ces garde-fous si tu l'adaptes.
- Pour **repérer** les dépôts touchés avant de lancer le prompt : `python3 detect/scan-workspace.py <dossier>` (working tree) puis `python3 detect/scan-git-history.py --root <dossier>` (tout l'historique, toutes les refs). Ce second scan dit aussi si le payload est **encore dans HEAD** ou seulement dans l'historique.
- Si seul le **working tree** est infecté (rien de committé), `clean/polinrider-clean.py` suffit : le prompt ci-dessous sert quand l'infection est dans des commits.
- Ne fais pas confiance à un nom de fichier : le prompt demande une détection **par le contenu** (signature binaire, bourrage d'espaces, marqueurs).

## Le prompt

````text
Ce dépôt est peut-être infecté par PolinRider (chaîne d'attaque : faux fichier de
police contenant du JS obfusqué, exécuté par une tâche VS Code à l'ouverture du
dossier). Nettoie-le en suivant ces étapes. Procède par étapes et arrête-toi pour
me demander confirmation avant toute action irréversible ou visible à l'extérieur
(force-push, création, renommage ou suppression de dépôt GitHub). Ne saisis jamais
de secret ni de clé. Rien ne doit être modifié sur GitHub avant mon accord.

## 1. État des lieux (lecture seule)
- Liste les branches locales et distantes, les tags, les stashes, les remotes.
  Utilise `git ls-remote origin` : le clone local peut ne suivre qu'une branche,
  alors que le distant en a d'autres (`master`, `refs/pull/*`).
- Fais un `git clone --mirror` du distant dans le scratchpad pour analyser TOUTES
  les refs sans toucher au dépôt ni au distant.

## 2. Détection, sur TOUS les commits de TOUTES les refs (pas seulement HEAD)
Indicateurs à chercher :
- Signatures : `global.i="A10`, `_0x1574`, `global['!']`, `rmcej`, `Cot%3t`,
  `temp_auto_push`, `temp_interactive_push`, `_$_xxxx`, `api.trongrid`, `aptoslabs`,
  `bsc-dataseed`.
- Auto-exécution : `.vscode/tasks.json` avec `runOn: folderOpen`, et
  `.vscode/settings.json` avec `task.allowAutomaticTasks`.
- Fichier déguisé : tout blob `.woff/.woff2/.ttf/.eot/.png/.jpg/.ico/...` dont les
  16 premiers octets sont du texte imprimable au lieu d'une signature binaire.
- Config piégée : ligne de plus de 1500 caractères dans `*.config.*`, `App.js`,
  `tailwind/postcss/eslint/vite/nuxt.config.*`.
- Artefacts : `.bat/.cmd/.ps1` suspects, entrées `.gitignore` qui masquent
  `temp_*push.bat` ou `branch_structure.json`.
- Historique : commits de type « remove virus », qui ont souvent retiré le
  déclencheur mais laissé le payload.
Exclus les fichiers qui parlent légitimement du sujet (articles, docs, garde CI).
Inspecte tout blob suspect avec `git cat-file -p <sha> | head -c 400 | cat -v` :
ne l'exécute JAMAIS. Donne-moi la liste exacte : chemins, commits, refs touchées.

## 3. Réécriture de l'historique
- Travaille dans une COPIE du miroir (`cp -a mirror.git clean.git`), jamais dans le
  dépôt réel.
- `git filter-repo --force --invert-paths --path <payload> --path <déclencheurs...>`
  avec les chemins trouvés à l'étape 2.
- Vérifie sur `clean.git` :
  a. zéro signature sur tous les commits, hors docs et garde ;
  b. zéro binaire déguisé ;
  c. le blob infecté n'existe plus (`git cat-file -e <sha>` échoue) ;
  d. `git rev-parse dev^{tree}` est identique à l'arbre du HEAD actuel, donc le
     contenu du site est inchangé.

## 4. Publication : nouveau dépôt plutôt que force-push
GitHub garde les anciens commits accessibles par SHA après un force-push, et
`refs/pull/*` ne se supprime pas. Il faut donc un dépôt neuf :
- Vérifie d'abord `gh repo view` (visibilité, branche par défaut) et les noms des
  secrets Actions (`gh secret list`) : ils sont perdus à la suppression.
- Crée le nouveau dépôt privé sous un nom PROVISOIRE, avec les mêmes propriétaire,
  visibilité et description. Si `.github/workflows` contient un déploiement sur
  push, désactive les Actions le temps du premier push, puis réactive-les.
- Pousse uniquement les branches (`git push origin refs/heads/x:refs/heads/x`),
  pas de `--mirror` ni de refs de PR. Pas de tags.
- Fais un clone frais du nouveau dépôt et rejoue toutes les vérifications de
  l'étape 3.
- Renomme l'ancien dépôt en `<nom>-infecte` (réversible), puis le nouveau au nom
  d'origine. NE SUPPRIME PAS l'ancien dépôt : c'est à moi de le faire.

## 5. Clone local
- `git fetch`, compare les arbres, puis `git reset --mixed origin/<branche>` : mes
  modifications non commitées doivent rester intactes (vérifie `git status` avant
  et après).
- Ne purge pas le reflog sans me demander.
- Supprime les miroirs temporaires du scratchpad.

## 6. Rapport final
Liste ce qui a été fait, puis ce qui reste à ma charge :
- supprimer l'ancien dépôt `-infecte` ;
- recréer les secrets Actions, avec une nouvelle clé SSH de déploiement ;
- changer par précaution tous les secrets exposés (`.env`, clés SSH, tokens
  GitHub et de déploiement) si le dossier a été ouvert dans VS Code pendant que
  `tasks.json` était actif ;
- refaire les clones sur les autres machines ;
- prévenir que les PR, issues et autres métadonnées de l'ancien dépôt ne sont pas
  migrées.
````

## Adapter le prompt

- **Branche de référence** : l'étape 3.d compare `dev^{tree}`. Remplace `dev` par la branche par défaut du dépôt (`main`, `master`…) et répète la comparaison pour chaque branche poussée.
- **Signatures** : si de nouvelles variantes apparaissent, mets d'abord à jour la liste de l'étape 2 avec [`indicators-of-compromise.md`](indicators-of-compromise.md).
- **Plusieurs dépôts** : lance le prompt une fois par dépôt. Pour repérer ceux qui sont touchés, commence par `python3 detect/scan-workspace.py --deep`.
- **Ce qui n'est pas migré** : PR, issues, wikis, releases, webhooks, déploiements et paramètres du dépôt. Note-les avant de renommer l'ancien dépôt.

## Après le nettoyage

La réécriture d'historique ne remplace pas le reste du playbook : rotation des secrets ([étape 2](playbook.md) et [étape 7](playbook.md)), réinstallation des machines infectées, ajout d'un scan IoC en CI et surveillance sur 30 jours.
