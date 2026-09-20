#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
triage-suspects.py — montre la PREUVE pour trancher : infection reelle ou faux positif. LECTURE SEULE.

Pour chaque suspect :
  - cherche les marqueurs PolinRider exacts (verdict immediat s'il y en a) ;
  - montre ce qui vient APRES le grand vide de la ligne visee (du code cache ? ou juste du texte ?) ;
  - montre la toute fin du fichier (la ou la charge est ajoutee).
Le contenu est affiche tronque et assaini (caracteres de controle remplaces) : rien n'est execute.

Usage :
    python3 detect/triage-suspects.py FICHIER[:LIGNE] [FICHIER[:LIGNE] ...]
    python3 detect/scan-workspace.py ~/projets --json | python3 detect/triage-suspects.py --from-scan -

Exemples de FICHIER[:LIGNE] : eslint.config.js:6   src/app.vue:23   postcss.config.mjs
--from-scan lit le JSON de scan-workspace.py (fichier ou « - » pour stdin) et triage chaque constat.
"""
import json
import os
import re
import sys

MARKERS = ["rmcej%otb%", "Cot%3t=shtP", "_$_1e42", "MDy(", "global['_V']", 'global["_V"]', "global['!']",
           'global["!"]', "2[gWfGj;<:-93Z^C", "m6:tTh^D)cBz?NM]", "A10-*40840", "temp_auto_push",
           "default-configuration.vercel.app", "260120.vercel.app", "vscode-settings",
           "api.trongrid", "aptoslabs.com"]
GAP = re.compile(r"(\S)([ \t]{30,})(\S.{0,90})")
CODEISH = re.compile(r"[(){}\[\];=]|=>|function|require|eval|global|const |let ")


def clean(s, n=160):
    s = "".join(c if c.isprintable() else "?" for c in s[:n])
    return s


def triage(fp, ln):
    print("=" * 74)
    print(fp + (f":{ln}" if ln else ""))
    if not os.path.isfile(fp):
        print("   (absent)")
        return
    try:
        txt = open(fp, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print("   (illisible)", e)
        return
    hits = [m for m in MARKERS if m in txt]
    if hits:
        print(f"   MARQUEUR PolinRider TROUVE : {hits}  -> INFECTE, aucun doute")
    else:
        print("   (aucun marqueur exact — on regarde le contexte)")
    print(f"   taille : {os.path.getsize(fp)} o")
    lines = txt.split("\n")
    if ln and 1 <= ln <= len(lines):
        m = GAP.search(lines[ln - 1])
        if m:
            after = m.group(3)
            verdict = "ressemble a du CODE (suspect)" if CODEISH.search(after) else "texte (probable faux positif)"
            print(f"   ligne {ln} : {len(m.group(2))} espaces puis {clean(after)!r}")
            print(f"      -> {verdict}")
        else:
            print(f"   ligne {ln} : pas de grand vide au milieu ({len(lines[ln - 1])} car.)")
    print(f"   fin du fichier : ...{clean(txt[-160:].replace(chr(10), '<NL>'))!r}")


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    targets = []
    if args[0] == "--from-scan":
        src = args[1] if len(args) > 1 else "-"
        data = json.load(sys.stdin if src == "-" else open(src, encoding="utf-8"))
        root = data.get("racine", "")
        for c in data.get("constats", []):
            targets.append((os.path.join(root, c["path"]), c.get("line")))
    else:
        for a in args:
            m = re.match(r"^(.*?)(?::(\d+))?$", a)
            targets.append((os.path.expanduser(m.group(1)), int(m.group(2)) if m.group(2) else None))
    seen = set()
    for fp, ln in targets:
        if (fp, ln) not in seen:
            seen.add((fp, ln))
            triage(fp, ln)
    print("=" * 74)


if __name__ == "__main__":
    main()
