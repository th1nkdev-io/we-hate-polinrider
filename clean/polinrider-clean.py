#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
polinrider-clean.py — Nettoyeur PolinRider du working tree (detection + eradication).
Multiplateforme (Linux / macOS / Windows), sans dependance externe.

PORTEE : les FICHIERS d'un dossier de projets. Ne touche ni a l'historique git, ni a GitHub :
pour un depot infecte deja committe/pousse, voir docs/prompt-nettoyage-depot.md.

Vecteurs traites (verdict par le CONTENU, jamais par le nom) :
  1. Configs / code injectes : payload colle en fin de fichier apres un bourrage de >= 100 espaces
     (postcss/tailwind/eslint/next/vite/webpack/astro/nuxt/rollup/svelte/babel/vue.config, App.js...)
     -> le fichier est TRONQUE juste avant le bourrage ; le code legitime est conserve.
  2. Fausses polices (.woff2/.woff/.ttf/.otf/.eot) : pas de signature de police ET debut en texte
     imprimable (= script deguise)                                          -> SUPPRIMEES.
  3. .vscode/tasks.json auto-executant : UUID StakingGame, ou runOn:folderOpen combine a une commande
     suspecte (node, curl|sh, tache masquee)                                -> SUPPRIME.
  4. .vscode/settings.json piege : `task.allowAutomaticTasks` actif et/ou bloc `tasks` folderOpen
                                                                            -> ces cles sont RETIREES.
  5. Fichiers IoC : temp_auto_push.bat, config.bat, branch_structure.json   -> SUPPRIMES.
  6. Paquets npm pieges (package.json / lockfiles), marqueurs et C2 hors bourrage,
     tasks.json folderOpen « ambigu » : SIGNALES seulement (« A REVOIR »), jamais modifies.

SURETE :
  - SIMULATION par defaut : rien n'est modifie sans --apply.
  - Avant toute action, chaque fichier touche est COPIE dans
    ~/_polinrider_quarantine/<horodatage>/<chemin relatif> -> reversible (cp -a pour restaurer).
  - Rien n'est execute ni importe : les fichiers sont lus comme des octets.
  - N'analyse pas node_modules / vendor / dist / .git ; ignore les liens symboliques.
  - Ne touche pas aux gardes defensives « security-guard* » (elles contiennent les signatures
    qu'elles traquent) ni a cette boite a outils.
  - Re-verifie apres nettoyage.

USAGE :
    python3 clean/polinrider-clean.py [DOSSIER]            # simulation (defaut : ~/_Workspace)
    python3 clean/polinrider-clean.py [DOSSIER] --apply    # applique (avec quarantaine)
    python3 clean/polinrider-clean.py [DOSSIER] --report   # detection seule, ne cree meme pas de quarantaine

Code de sortie : 0 = rien ; 1 = uniquement des « A REVOIR » ; 2 = des actions automatiques existent
(simulation/rapport) ; apres --apply : 0 si tout est propre, 3 si un element resiste.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import sys

# --------------------------------------------------------------------------- IoC
EXCLUDE = {"node_modules", "dist", "build", "out", ".git", ".nuxt", ".output", ".next", ".cache",
           ".data", "vendor", "vendors", "coverage", ".turbo", ".pnpm-store", ".venv", "venv",
           "__pycache__", "bower_components", "we-hate-polinrider", "_polinrider_quarantine"}
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".vue", ".svelte", ".astro"}
FONT_EXT = {".woff2", ".woff", ".ttf", ".otf", ".eot"}
FONT_MAGICS = (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf")
LOCK_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
              "pnpm-lock.yaml", "bun.lock"}
IOC_FILES = {"temp_auto_push.bat", "config.bat", "branch_structure.json"}
UUID = "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"

MARKERS = [
    "rmcej%otb%", "Cot%3t=shtP", "_$_1e42", "global['_V']", 'global["_V"]', "global['!']", 'global["!"]',
    "2[gWfGj;<:-93Z^C", "m6:tTh^D)cBz?NM]", "A10-*40840", "temp_auto_push",
    "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP", "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG",
    "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e",
    "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3", UUID,
]
C2 = ["default-configuration.vercel.app", "260120.vercel.app",
      "vscode-settings-bootstrap.vercel.app", "vscode-settings-config.vercel.app",
      "vscode-bootstrapper.vercel.app", "vscode-load-config.vercel.app",
      "api.trongrid.io", "fullnode.mainnet.aptoslabs.com"]
MAL_PKGS = ["tailwindcss-style-animate", "tailwind-mainanimation", "tailwind-autoanimation",
            "tailwind-animationbased", "tailwindcss-typography-style", "tailwindcss-style-modify",
            "tailwindcss-animate-style"]

# Bourrage : >= 100 espaces/tabs SUIVIS de code sur la meme ligne (la charge est collee apres).
PAD = re.compile(r"[ \t]{100,}(?=[^ \t\r\n])")
# Signature du payload qui suit le bourrage.
PAYLOAD = re.compile(r"global\.i\s*=|\brun\(\)\s*;|(?:_0x[0-9a-f]{4,}.*){3,}|"
                     + "|".join(re.escape(m) for m in MARKERS))
MAX_LINES_AFTER = 3   # au-dela, on ne tronque pas automatiquement : « A REVOIR »
MAX_READ = 5_000_000  # octets lus par fichier de code

# --------------------------------------------------------------------------- etat
actions = []   # (verbe, chemin, detail)
signals = []   # (chemin, detail)


def is_minified(name):
    low = name.lower()
    return ".min." in low or ".bundle." in low


def read_bytes(path, limit=MAX_READ):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit + 1)
    except OSError:
        return None


def as_text(data):
    # latin-1 : aller-retour exact octet par octet, les marqueurs sont en ASCII.
    return data.decode("latin-1")


def is_printable_text(head):
    return bool(head) and all(b in (9, 10, 13) or 32 <= b < 127 for b in head)


# ----------------------------------------------------------------------- controles
def check_font(fp):
    head = read_bytes(fp, 4096)
    if not head:
        return
    ext = os.path.splitext(fp)[1].lower()
    if ext == ".eot":
        ok = len(head) >= 36 and head[34:36] == b"\x4c\x50"   # MagicNumber EOT 0x504C
    else:
        ok = head[:4] in FONT_MAGICS
    if ok:
        return
    if is_printable_text(head[:16]):
        actions.append(("SUPPR police", fp, "pas une police : debut en texte = script deguise"))
    else:
        signals.append((fp, f"police sans signature connue (debut {head[:4]!r}) — binaire, a verifier"))


def tasks_verdict(text):
    """'sure' = auto-executant et malveillant ; 'maybe' = folderOpen sans preuve ; None = rien."""
    low = text.lower()
    if UUID in text:
        return "sure"
    if "folderopen" not in low:
        return None
    suspicious = (re.search(r'"command"\s*:\s*"[^"]*\bnode\b', text)
                  or re.search(r"(?:curl|wget)[^\n|]*\|\s*(?:ba|z)?sh\b", text)
                  or re.search(r"node\s+[^\s\"']+\.(?:woff2?|ttf|otf|eot|dict)\b", text)
                  or re.search(r'"reveal"\s*:\s*"(?:never|silent)"|"hide"\s*:\s*true', text))
    return "sure" if suspicious else "maybe"


def check_tasks(fp):
    data = read_bytes(fp)
    if data is None:
        return
    v = tasks_verdict(as_text(data))
    if v == "sure":
        actions.append(("SUPPR tasks", fp, "auto-execution (folderOpen + commande suspecte / UUID StakingGame)"))
    elif v == "maybe":
        signals.append((fp, "tasks.json avec runOn: folderOpen mais sans commande suspecte — lire le fichier"))


def settings_bad_keys(data):
    bad = []
    aat = data.get("task.allowAutomaticTasks")
    if aat is True or aat == "on":
        bad.append("task.allowAutomaticTasks")
    if isinstance(data.get("tasks"), dict) and "folderopen" in json.dumps(data["tasks"]).lower():
        bad.append("tasks (folderOpen)")
    return bad


def check_settings(fp):
    data = read_bytes(fp)
    if data is None:
        return
    raw = as_text(data)
    if "allowAutomaticTasks" not in raw and "folderOpen" not in raw:
        return
    try:
        parsed = json.loads(raw)
    except ValueError:
        signals.append((fp, "settings.json suspect mais JSON illisible (commentaires ?) — a nettoyer a la main"))
        return
    if isinstance(parsed, dict):
        bad = settings_bad_keys(parsed)
        if bad:
            actions.append(("NETTOYER settings", fp, "retirer : " + ", ".join(bad)))


def truncation_point(txt):
    """Index de coupe (debut du bourrage) si la fin du fichier ressemble a une charge ajoutee, sinon None.
    Verdict a 3 etats : (index, None) = tronquer ; (None, raison) = a revoir ; (None, None) = rien."""
    for m in PAD.finditer(txt):
        eol = txt.find("\n", m.end())
        line_rest = txt[m.end(): eol if eol != -1 else len(txt)]
        if not PAYLOAD.search(line_rest):
            continue
        after = [ln for ln in txt[eol:].split("\n")[1:] if ln.strip()] if eol != -1 else []
        if len(after) > MAX_LINES_AFTER:
            return None, f"bourrage + charge en ligne {txt.count(chr(10), 0, m.start()) + 1} mais {len(after)} lignes suivent"
        return m.start(), None
    return None, None


def check_code(fp, name):
    if is_minified(name):
        return
    data = read_bytes(fp)
    if data is None or b"\x00" in data[:8192]:
        return
    txt = as_text(data)
    cut, why = truncation_point(txt)
    if cut is not None:
        clean_len = len(txt[:cut].rstrip()) + 1
        actions.append(("TRONQUER", fp, f"{len(txt)} o -> {clean_len} o (charge retiree, code legitime conserve)"))
        return
    if why:
        signals.append((fp, why + " — verifier a la main"))
        return
    for mk in MARKERS:
        if mk in txt:
            signals.append((fp, f"marqueur « {mk} » hors bourrage"))
            return
    for d in C2:
        if d in txt:
            signals.append((fp, f"domaine C2 « {d} »"))
            return


def check_pkg(fp):
    data = read_bytes(fp)
    if data is None:
        return
    raw = as_text(data)
    for p in MAL_PKGS:
        if f'"{p}"' in raw or f"{p}@" in raw:
            signals.append((fp, f"paquet npm PIEGE « {p} » — a retirer + regenerer le lockfile"))


# ----------------------------------------------------------------------- application
def quarantine(fp, root, qroot):
    dest = os.path.join(qroot, os.path.relpath(fp, root))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(fp, dest)


def apply_action(kind, fp):
    if kind.startswith("SUPPR"):
        os.remove(fp)
    elif kind == "TRONQUER":
        txt = as_text(read_bytes(fp))
        cut, _ = truncation_point(txt)
        if cut is None:
            raise RuntimeError("le fichier a change depuis l'analyse")
        with open(fp, "wb") as fh:
            fh.write((txt[:cut].rstrip() + "\n").encode("latin-1"))
    elif kind == "NETTOYER settings":
        parsed = json.loads(as_text(read_bytes(fp)))
        parsed.pop("task.allowAutomaticTasks", None)
        parsed.pop("tasks", None)
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(parsed, fh, indent=2, ensure_ascii=False)
            fh.write("\n")


def still_infected(kind, fp):
    if kind.startswith("SUPPR"):
        return os.path.exists(fp)
    data = read_bytes(fp)
    if data is None:
        return False
    if kind == "TRONQUER":
        return truncation_point(as_text(data))[0] is not None
    if kind == "NETTOYER settings":
        raw = as_text(data)
        return "allowAutomaticTasks" in raw or "folderOpen" in raw
    return False


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Nettoyeur PolinRider (simulation par defaut).")
    ap.add_argument("root", nargs="?", default="~/_Workspace", help="dossier de projets (defaut : ~/_Workspace)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="applique les actions (avec quarantaine)")
    mode.add_argument("--report", action="store_true", help="detection seule, aucune ecriture")
    args = ap.parse_args()

    root = os.path.abspath(os.path.expanduser(args.root))
    if not os.path.isdir(root):
        sys.exit(f"Dossier introuvable : {root}")
    rel = lambda p: os.path.relpath(p, root)

    nfiles = 0
    for dp, dn, fns in os.walk(root, followlinks=False):
        dn[:] = [d for d in dn if d not in EXCLUDE and not os.path.islink(os.path.join(dp, d))]
        for fn in fns:
            fp = os.path.join(dp, fn)
            if os.path.islink(fp):
                continue
            nfiles += 1
            low = fn.lower()
            ext = os.path.splitext(fn)[1].lower()
            if "security-guard" in low:            # garde defensive : on n'y touche pas
                continue
            if low in IOC_FILES:
                actions.append(("SUPPR IoC", fp, f"fichier IoC « {fn} »"))
                continue
            parent = os.path.basename(dp)
            if low == "tasks.json" and parent == ".vscode":
                check_tasks(fp)
                continue
            if low == "settings.json" and parent == ".vscode":
                check_settings(fp)
                continue
            if low in LOCK_FILES:
                check_pkg(fp)
            if ext in FONT_EXT:
                check_font(fp)
            elif ext in CODE_EXT:
                check_code(fp, fn)

    label = "APPLICATION" if args.apply else ("RAPPORT (lecture seule)" if args.report else "SIMULATION")
    print(f"PolinRider — nettoyeur   |   mode : {label}")
    print(f"Cible : {root}   ({nfiles} fichiers examines)")
    print("=" * 74)
    if not actions and not signals:
        print("Aucune infection detectee.")
        return 0

    for kind, fp, detail in actions:
        print(f"[{kind}] {rel(fp)}\n        {detail}")
    if signals:
        print("-" * 74)
        for fp, detail in signals:
            print(f"[A REVOIR] {rel(fp)}\n        {detail}")
    print("=" * 74)
    counts = {}
    for kind, *_ in actions:
        counts[kind.split()[0]] = counts.get(kind.split()[0], 0) + 1
    print("Actions automatiques : " + (", ".join(f"{v} {k}" for k, v in counts.items()) or "aucune")
          + f"   |   a revoir a la main : {len(signals)}")

    if not args.apply:
        if not args.report and actions:
            print("\nSIMULATION — rien n'a ete modifie. Pour appliquer (quarantaine reversible) :")
            print(f'     python3 {sys.argv[0]} "{root}" --apply')
        return 2 if actions else 1

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    qroot = os.path.expanduser(f"~/_polinrider_quarantine/{stamp}")
    print(f"\nQuarantaine -> {qroot}")
    failed = 0
    for kind, fp, _ in actions:
        try:
            quarantine(fp, root, qroot)
            apply_action(kind, fp)
        except Exception as e:                 # on n'ecrase jamais sans copie de secours
            failed += 1
            print(f"  ECHEC sur {rel(fp)} : {e}")

    print("\nVerification post-nettoyage...")
    left = sum(1 for kind, fp, _ in actions if still_infected(kind, fp))
    for kind, fp, _ in actions:
        if still_infected(kind, fp):
            print(f"  encore infecte : {rel(fp)}")
    print("  Tout est nettoye." if not left and not failed else f"  {left + failed} element(s) a reverifier.")
    print(f"\nOriginaux conserves dans : {qroot}")
    print(f'Restaurer un fichier : cp -a "{qroot}/<chemin relatif>" "{root}/<chemin relatif>"')
    if signals:
        print("Les « A REVOIR » (marqueurs, C2, paquets npm, tasks ambigus) ne sont PAS traites : lis-les.")
    print("Ensuite : `git status` puis relis les diffs. Si l'infection est dans l'HISTORIQUE git "
          "(commits deja pousses), voir docs/prompt-nettoyage-depot.md.")
    return 3 if (left or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
