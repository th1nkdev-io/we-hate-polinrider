# we-hate-polinrider

Boîte à outils et méthode pour **détecter, contenir et se remettre** d'une compromission par **PolinRider** — une campagne de supply-chain (attribuée à l'acteur nord-coréen Lazarus) qui vole identifiants, cookies de session et wallets, et se propage via GitHub en utilisant *tes* identifiants Git.

Tous les scripts sont **auditables** et, pour les détecteurs et l'audit serveur, **en lecture seule** : ils ne suppriment ni ne modifient rien. Lis le code avant de l'exécuter.

> ⚠️ **N'exécute jamais un « nettoyeur PolinRider » tout fait téléchargé au hasard.** Les faux outils de remédiation sont un vecteur de second niveau typique de cette campagne. Ici, tout est lisible et sans binaire.

## Les 3 règles qui ne se négocient pas
1. **Ne jamais saisir un nouveau mot de passe sur une machine encore infectée** — le voleur le capture. Utilise un téléphone ou une machine saine.
2. **Ne jamais se reconnecter (SSH, `git push`) depuis une machine infectée** avant réinstallation — chaque connexion re-propage la charge.
3. **Se méfier des nettoyeurs tout faits** — n'exécute que des scripts dont tu as lu le code.

## Contenu

```
docs/
  playbook.md                       Procédure d'éradication complète en 8 étapes
  indicators-of-compromise.md       Liste des IoC (détecter par le CONTENU, pas le nom)
detect/
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
2. **Détecter** avec le script `detect/` adapté à l'OS.
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
