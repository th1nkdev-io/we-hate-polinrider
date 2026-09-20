#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
restore-rescue.py — Réconcilie RESCUE_SLIM avec les clones ~/_Workspace/<compte>/<repo>.
Correspondance par le REMOTE git (colonne 2 du _manifest.tsv).

VERSION ÉCONOME EN DATA :
  - Par défaut : n'applique QUE les patches (modifs non commitées) + les fichiers
    non suivis (.env, etc.). AUCUN téléchargement réseau. Instantané.
  - --bundles : réintègre aussi les commits non poussés (.bundle / .stash.bundle).
    Nécessite un peu d'historique : le script le descend PROGRESSIVEMENT (--deepen),
    pas tout d'un coup. À réserver aux repos où tu en as besoin (avec --only).

Idempotent : un patch déjà appliqué est détecté et sauté → relançable sans risque.

Usage :
  python3 restore-rescue.py                         # léger (patch+untracked), zéro data
  python3 restore-rescue.py --only monprojet        # cible un/des repo(s)
  python3 restore-rescue.py --bundles --only motodigo   # + commits non poussés, ciblé
  python3 restore-rescue.py --dry-run               # simulation (ne modifie rien)
  python3 restore-rescue.py --rescue=~/backup/RESCUE_SLIM   # dossier RESCUE explicite
  python3 restore-rescue.py --deny=un-client        # ignore les remotes contenant ce texte (repetable)
"""

import os, re, sys, subprocess, tarfile

HOME      = os.path.expanduser("~")
WORKSPACE = os.path.join(HOME, "_Workspace")

# dossier RESCUE : --rescue=CHEMIN, sinon le bon dossier (« RESCUE_SLIM (2) » de préférence)
RESCUE = None
for a in sys.argv:
    if a.startswith("--rescue="):
        RESCUE = os.path.expanduser(a.split("=", 1)[1])
if not RESCUE:
    for cand in (os.path.join(WORKSPACE, "RESCUE_SLIM (2)"),
                 os.path.join(WORKSPACE, "RESCUE_SLIM")):
        if os.path.isdir(cand):
            RESCUE = cand; break
    else:
        RESCUE = os.path.join(WORKSPACE, "RESCUE_SLIM")
MANIFEST  = os.path.join(RESCUE, "_manifest.tsv")

DRY      = "--dry-run" in sys.argv
BUNDLES  = "--bundles" in sys.argv
ONLY     = None
for i, a in enumerate(sys.argv):
    if a == "--only" and i + 1 < len(sys.argv):
        ONLY = sys.argv[i + 1]
    elif a.startswith("--only="):
        ONLY = a.split("=", 1)[1]

# Remotes a ignorer (sous-chaine), ex. un depot client deja nettoye de son cote : --deny=un-client
DENY_REMOTE = tuple(a.split("=", 1)[1].lower() for a in sys.argv if a.startswith("--deny="))

def norm(url):
    u = (url or "").strip()
    if not u:
        return None
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    m = re.match(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$", u)
    if m:
        return (m.group(1) + "/" + m.group(2)).lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^ssh://", "", u)
    return u.lower()

def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True)

def build_clone_index():
    # Trouve TOUS les dépôts git sous _Workspace, à n'importe quelle profondeur
    # (les arborescences imbriquées type compte/projet/depot sont gérées).
    index = {}
    if not os.path.isdir(WORKSPACE):
        return index
    SKIP = {"node_modules", "RESCUE_SLIM", "vendor", "dist", ".next", ".nuxt"}
    for dp, dn, fns in os.walk(WORKSPACE):
        dn[:] = [d for d in dn if d not in SKIP]
        if os.path.isdir(os.path.join(dp, ".git")):
            r = git(dp, "remote", "get-url", "origin")
            key = norm(r.stdout.strip()) if r.returncode == 0 else None
            if key:
                index[key] = dp
            dn[:] = []          # ne pas descendre dans un dépôt (évite les sous-modules)
    return index

def read_manifest():
    rows = []
    with open(MANIFEST, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            rows.append((parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""))
    return rows

def artifacts_for(base):
    out = {}
    for kind, suf in (("bundle", ".bundle"), ("stash", ".stash.bundle"),
                      ("patch", ".uncommitted.patch"), ("untracked", ".untracked.tgz")):
        p = os.path.join(RESCUE, base + suf)
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            out[kind] = p
    return out

def is_shallow(clone):
    return os.path.isfile(os.path.join(clone, ".git", "shallow"))

def deepen_until_bundle_ok(clone, bundle, log):
    if git(clone, "bundle", "verify", bundle).returncode == 0:
        return True
    if not is_shallow(clone):
        return False
    for _ in range(10):                       # jusqu'à ~500 commits d'historique
        r = git(clone, "fetch", "--deepen", "50")
        if git(clone, "bundle", "verify", bundle).returncode == 0:
            return True
        if r.returncode != 0:
            break
        if not is_shallow(clone):             # historique complet atteint
            return git(clone, "bundle", "verify", bundle).returncode == 0
    return False

def apply_bundle(clone, path, log):
    if not deepen_until_bundle_ok(clone, path, log):
        log.append("      bundle : base introuvable même après --deepen — ignoré")
        return
    r = git(clone, "fetch", path, "refs/heads/*:refs/heads/rescue/*")
    if r.returncode == 0:
        b = git(clone, "branch", "--list", "rescue/*")
        names = ", ".join(x.strip("* ").strip() for x in b.stdout.splitlines() if x.strip())
        log.append(f"      commits non poussés -> {names or 'rescue/*'}")
    else:
        log.append(f"      bundle : {r.stderr.strip()[:100]}")

def apply_stash(clone, path, log):
    r = git(clone, "fetch", path, "refs/*:refs/rescue-stash/*")
    log.append("      stashes -> refs/rescue-stash/* " +
               ("(ok)" if r.returncode == 0 else "(échec)"))

def apply_patch(clone, path, log):
    # déjà appliqué ? (le patch inverse s'applique proprement)
    if git(clone, "apply", "--reverse", "--check", path).returncode == 0:
        log.append("      modifs non commitées -> déjà présentes (sauté)")
        return
    if git(clone, "apply", "--check", path).returncode == 0:
        git(clone, "apply", path)
        log.append("      modifs non commitées -> appliquées")
        return
    if git(clone, "apply", "--3way", path).returncode == 0:
        log.append("      modifs non commitées -> appliquées (--3way)")
    else:
        git(clone, "apply", "--reject", path)
        log.append("      modifs non commitées -> CONFLITS (.rej créés, à revoir)")

def apply_untracked(clone, path, log):
    n = 0
    try:
        with tarfile.open(path, "r:gz") as t:
            for m in t.getmembers():
                dest = os.path.join(clone, m.name)
                if os.path.exists(dest):
                    continue                  # ne jamais écraser
                t.extract(m, clone)
                if m.isfile():
                    n += 1
    except Exception as e:
        log.append(f"      untracked : erreur {e}")
        return
    log.append(f"      fichiers non suivis (.env, etc.) -> {n} nouveau(x)")

def main():
    if not os.path.isfile(MANIFEST):
        print("Manifeste introuvable :", MANIFEST); sys.exit(1)

    index = build_clone_index()
    rows = read_manifest()

    mode = "SIMULATION" if DRY else "APPLICATION"
    print(f"Mode : {mode}   |   Bundles : {'OUI' if BUNDLES else 'non (léger)'}"
          + (f"   |   --only {ONLY}" if ONLY else ""))
    print(f"RESCUE : {RESCUE}")
    print(f"Clones : {len(index)}   Entrées : {len(rows)}")
    print("=" * 68)

    done = nomatch = 0
    missing = []          # (base, remote, artefacts) : ont du contenu RESCUE mais pas de clone
    for base, remote in rows:
        key = norm(remote)
        if key and any(d in key for d in DENY_REMOTE):
            continue
        arts = artifacts_for(base)
        if not arts:
            continue
        if ONLY and ONLY.lower() not in base.lower() and ONLY.lower() not in (remote or "").lower():
            continue
        clone = index.get(key)
        if not clone:
            nomatch += 1
            missing.append((base, remote, sorted(arts)))
            continue

        rel = os.path.relpath(clone, WORKSPACE)
        will = [k for k in arts if BUNDLES or k in ("patch", "untracked")]
        if not will:
            continue
        done += 1
        print(f"[{rel}]  ({'+'.join(sorted(will))})")
        if not DRY:
            log = []
            if BUNDLES and "bundle" in arts: apply_bundle(clone, arts["bundle"], log)
            if BUNDLES and "stash" in arts:  apply_stash(clone, arts["stash"], log)
            if "patch" in arts:              apply_patch(clone, arts["patch"], log)
            if "untracked" in arts:          apply_untracked(clone, arts["untracked"], log)
            for l in log:
                print(l)

    print("=" * 68)
    print(f"Traités : {done}   |   sans clone : {nomatch}")
    if missing:
        print("\nSANS CLONE — ont une sauvegarde RESCUE mais aucun clone local")
        print("(à cloner depuis GitHub, puis relancer restore-rescue) :")
        for base, remote, arts in sorted(missing, key=lambda x: x[1] or ""):
            r = remote if remote else "(dépôt LOCAL, pas de remote)"
            print(f"  • {r}")
            print(f"      artefacts : {'+'.join(arts)}")
    if not BUNDLES:
        print("\nCommits non poussés (bundles) NON traités → relancer avec --bundles --only <repo>")

if __name__ == "__main__":
    main()
