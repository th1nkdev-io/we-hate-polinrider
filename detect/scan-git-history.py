#!/usr/bin/env python3
"""
scan-git-history.py — cherche PolinRider dans TOUT l'historique git (toutes les refs), pas seulement HEAD.

Pourquoi : un « remove virus » retire souvent le declencheur (tasks.json) mais laisse le payload dans
un commit ancien ; un working tree propre ne prouve rien. GitHub sert aussi les anciens commits par SHA
et garde refs/pull/*. Ce script repond a : « le blob infecte existe-t-il encore quelque part ? »

LECTURE SEULE :
  - n'appelle que des commandes git de lecture (rev-list, cat-file, log, for-each-ref, ls-tree) ;
  - le contenu des blobs est lu comme des OCTETS : rien n'est execute, importe ni ecrit sur disque ;
  - ne modifie ni le depot ni le distant.

Usage :
    python3 detect/scan-git-history.py                       # depot courant
    python3 detect/scan-git-history.py DEPOT [DEPOT ...]     # un ou plusieurs depots (ou miroirs .git)
    python3 detect/scan-git-history.py --root ~/_Workspace   # decouvre tous les depots sous un dossier
    python3 detect/scan-git-history.py --json > rapport.json

Pour analyser TOUTES les refs du distant (branches, refs/pull/*) sans toucher au clone local :
    git clone --mirror <url> /chemin/scratch/depot.git && python3 detect/scan-git-history.py /chemin/scratch/depot.git

Regles : les memes que detect/scan-workspace.py (marqueurs, bourrage d'espaces, fausses polices verifiees
par signature binaire, tasks.json / settings.json auto-executants, fichiers IoC, paquets npm pieges).
Perimetre : polices, .vscode/tasks.json|settings.json, configs ciblees, fichiers de code, fichiers .bat/.ps1/.sh,
lockfiles. Les autres .json et les blobs > --max-size sont ignores (comptes dans le resume).

Code de sortie : 0 = rien, 1 = uniquement MOYEN, 2 = au moins un HAUT.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("scan_workspace", HERE / "scan-workspace.py")
sw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sw)      # definit seulement les regles : main() ne s'execute pas a l'import

HIGH, MED = sw.HIGH, sw.MED
IOC_NAMES = {"temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"}
IOC_MED_NAMES = {"config.bat"}
SUSPECT_MSG = re.compile(r"remove[ _-]*(the[ _-]*)?(virus|malware)|polinrider|malicious|infect", re.I)
SCAN_EXTS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".vue", ".svelte",
             ".astro", ".dict", ".bat", ".cmd", ".ps1", ".sh"} | sw.FONT_EXTS
BATCH = 40


def git(repo, *args, data=None, check=True):
    r = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="replace").strip() or f"git {' '.join(args)} a echoue")
    return r


def find_repos(root):
    out = []
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        d = Path(dirpath)
        if (d / ".git").exists() or (d.name.endswith(".git") and (d / "HEAD").is_file() and (d / "objects").is_dir()):
            out.append(d)
            dirnames[:] = []
            continue
        dirnames[:] = [n for n in dirnames if n not in ("node_modules", ".venv", "venv", "vendor")
                       and not (d / n).is_symlink()]
    return sorted(out)


def interesting(path):
    """Renvoie la classe de controle a appliquer a ce chemin, ou None."""
    p = PurePosixPath(path)
    name, ext = p.name, p.suffix.lower()
    if name in IOC_NAMES or name in IOC_MED_NAMES or name == "spellright.dict":
        return "ioc"
    if ext in sw.FONT_EXTS:
        return "font"
    if name == "tasks.json" and p.parent.name == ".vscode":
        return "tasks"
    if name == "settings.json" and p.parent.name == ".vscode":
        return "settings"
    if name in sw.PKG_FILES:
        return "pkg"
    if ext in SCAN_EXTS or name in sw.CONFIG_TARGETS:
        return "code"
    return None


def read_blobs(repo, shas):
    """{sha: bytes} via git cat-file --batch (octets bruts, jamais executes)."""
    res = {}
    for i in range(0, len(shas), BATCH):
        chunk = shas[i:i + BATCH]
        raw = git(repo, "cat-file", "--batch", data=("\n".join(chunk) + "\n").encode()).stdout
        pos = 0
        for _ in chunk:
            nl = raw.index(b"\n", pos)
            head = raw[pos:nl].split()
            if len(head) < 3:                       # « <sha> missing »
                pos = nl + 1
                continue
            size = int(head[2])
            res[head[0].decode()] = raw[nl + 1: nl + 1 + size]
            pos = nl + 1 + size + 1
    return res


def scan_blob(kind, path, data):
    rep = sw.Report()
    p = PurePosixPath(path)
    name = p.name
    is_target, is_entry = name in sw.CONFIG_TARGETS, name in sw.ENTRY_TARGETS
    if kind == "ioc":
        sw.check_ioc_file(rep, p, data)
    elif kind == "font":
        sw.check_font(rep, p, data)
    elif kind == "tasks":
        sw.check_tasks_json(rep, p, data)
    elif kind == "settings":
        sw.check_settings_json(rep, p, data)
    elif kind == "pkg":
        for m in sw.PKG_RE.finditer(data):
            rep.add(HIGH, p, sw.line_of(data, m.start()), f"paquet npm piege : {m.group(1).decode()}")
    if b"\x00" not in data[:8192]:              # texte : une vraie police binaire est ecartee ici
        sw.check_strings(rep, p, data, sensitive=is_target or is_entry or kind in ("tasks", "settings"))
    if kind == "code" and not name.endswith((".min.js", ".min.mjs")) and b"\x00" not in data[:8192]:
        sw.check_padding(rep, p, data, target=is_target or is_entry, min_tail=20 if is_target else 100)
    if kind == "code" and is_target and len(data) >= sw.BIG_CONFIG:
        rep.add(MED, p, None, f"config de {len(data)} octets (saine ~80-200, infectee ~5000) — a relire")
    return rep.sorted()


def locate(repo, sha):
    """Commits qui introduisent/retirent ce blob (git log --find-object), + refs qui les contiennent."""
    r = git(repo, "log", "--all", f"--find-object={sha}", "--format=%h %ad %s", "--date=short", check=False)
    lines = [ln for ln in r.stdout.decode(errors="replace").splitlines() if ln.strip()]
    if not lines:
        return None, []
    first = lines[-1]                                   # le plus ancien = introduction
    h = first.split()[0]
    refs = git(repo, "for-each-ref", f"--contains={h}", "--format=%(refname:short)", check=False)
    names = [x for x in refs.stdout.decode(errors="replace").split() if x]
    return first, names


def scan_repo(repo, max_size, detail_cap, include_self):
    out = {"depot": str(repo), "constats": [], "ignores_taille": 0, "objets_lus": 0, "refs": 0,
           "refs_pull": 0, "note": ""}
    refs = git(repo, "for-each-ref", "--format=%(refname)").stdout.decode().split()
    out["refs"] = len(refs)
    out["refs_pull"] = sum(r.startswith("refs/pull/") for r in refs)
    if not refs:
        out["note"] = "aucune ref (depot vide ?)"
        return out
    if not include_self and git(repo, "cat-file", "-e", "HEAD:docs/indicators-of-compromise.md",
                                check=False).returncode == 0:
        out["note"] = "boite a outils we-hate-polinrider detectee : ignoree (--include-self pour forcer)"
        return out

    # 1. tous les blobs de tous les commits de toutes les refs
    listing = git(repo, "rev-list", "--objects", "--all").stdout.decode(errors="replace").splitlines()
    todo = {}                                           # sha -> (kind, [chemins])
    for ln in listing:
        sha, _, path = ln.partition(" ")
        if not path:
            continue
        kind = interesting(path)
        if kind:
            todo.setdefault(sha, (kind, []))[1].append(path)
    # 2. filtrer par type/taille
    shas = list(todo)
    sizes = {}
    for i in range(0, len(shas), 500):
        chunk = shas[i:i + 500]
        raw = git(repo, "cat-file", "--batch-check", data=("\n".join(chunk) + "\n").encode()).stdout.decode()
        for ln in raw.splitlines():
            parts = ln.split()
            if len(parts) == 3 and parts[1] == "blob":
                sizes[parts[0]] = int(parts[2])
    keep = []
    for sha in shas:
        if sha not in sizes:
            continue                                    # arbre / commit / manquant
        kind, paths = todo[sha]
        if sizes[sha] > max_size and kind not in ("ioc",):
            out["ignores_taille"] += 1
            if any(PurePosixPath(p).name in sw.CONFIG_TARGETS for p in paths):
                out["constats"].append({"sev": HIGH, "path": paths[0], "sha": sha, "line": None,
                                        "rule": f"fichier cible de {sizes[sha]} octets (trop gros pour une config)"})
            continue
        keep.append(sha)
    blobs = read_blobs(repo, keep)
    out["objets_lus"] = len(blobs)

    head_blobs = {}
    ls = git(repo, "ls-tree", "-r", "HEAD", check=False).stdout.decode(errors="replace")
    for ln in ls.splitlines():
        meta, _, path = ln.partition("\t")
        head_blobs[path] = meta.split()[2] if len(meta.split()) >= 3 else ""

    # 3. controles
    for sha, data in blobs.items():
        kind, paths = todo[sha]
        path = paths[0]
        findings = scan_blob(kind, path, data)
        if kind == "ioc" and not findings and PurePosixPath(path).name in IOC_NAMES:
            findings = [{"sev": HIGH, "rule": f"fichier IoC {PurePosixPath(path).name} present dans l'historique",
                         "line": None, "detail": ""}]
        for f in findings:
            out["constats"].append({"sev": f["sev"], "path": path, "sha": sha, "line": f["line"],
                                    "rule": f["rule"], "en_head": any(head_blobs.get(p) == sha for p in paths),
                                    "autres_chemins": paths[1:4]})

    # 4. messages de commit evocateurs
    log = git(repo, "log", "--all", "--format=%h %s", check=False).stdout.decode(errors="replace")
    for ln in log.splitlines():
        if SUSPECT_MSG.search(ln):
            out["constats"].append({"sev": MED, "path": "(message de commit)", "sha": "", "line": None,
                                    "rule": "commit de « nettoyage » : a verifier (retire souvent le declencheur "
                                            "mais laisse le payload) : " + ln[:100]})

    order = {HIGH: 0, MED: 1}
    out["constats"].sort(key=lambda c: (order[c["sev"]], c["path"], c["sha"]))
    for c in out["constats"][:detail_cap]:
        if c.get("sha"):
            c["commit"], c["refs"] = locate(repo, c["sha"])
    return out


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description="Scanner PolinRider de tout l'historique git (lecture seule).")
    ap.add_argument("repos", nargs="*", help="depots (ou miroirs .git) ; defaut : depot courant")
    ap.add_argument("--root", help="decouvre et scanne tous les depots sous ce dossier")
    ap.add_argument("--max-size", type=int, default=2_000_000, help="taille max d'un blob lu (octets)")
    ap.add_argument("--detail-cap", type=int, default=40, help="nb max de constats localises (commit/refs)")
    ap.add_argument("--include-self", action="store_true", help="scanner aussi la boite a outils elle-meme")
    ap.add_argument("--json", action="store_true", help="sortie JSON")
    args = ap.parse_args()

    repos = [Path(r).expanduser().resolve() for r in args.repos]
    if args.root:
        repos += find_repos(Path(args.root).expanduser().resolve())
    if not repos:
        repos = [Path.cwd()]
    results = []
    for r in repos:
        try:
            git(r, "rev-parse", "--git-dir")
            results.append(scan_repo(r, args.max_size, args.detail_cap, args.include_self))
        except (RuntimeError, OSError, ValueError) as e:
            results.append({"depot": str(r), "constats": [], "note": f"illisible : {e}"})

    n_high = sum(c["sev"] == HIGH for r in results for c in r["constats"])
    n_med = sum(c["sev"] == MED for r in results for c in r["constats"])
    if args.json:
        json.dump({"haut": n_high, "moyen": n_med, "depots": results}, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print(f"### SCAN DE L'HISTORIQUE GIT (lecture seule) — {len(results)} depot(s)")
        for r in results:
            print(f"\n=== {r['depot']}")
            if r.get("note"):
                print(f"  ({r['note']})")
            if r.get("refs") is not None and "objets_lus" in r:
                extra = f", dont {r['refs_pull']} refs/pull/*" if r.get("refs_pull") else ""
                print(f"  {r['refs']} refs{extra} ; {r['objets_lus']} blobs analyses"
                      + (f" ; {r['ignores_taille']} ignores (> {args.max_size} o)" if r["ignores_taille"] else ""))
            if not r["constats"]:
                if "objets_lus" in r and r["objets_lus"]:
                    print("  OK : aucun indicateur dans l'historique")
                continue
            for c in r["constats"]:
                loc = c["path"] + (f":{c['line']}" if c.get("line") else "")
                tag = ""
                if c.get("sha"):
                    tag = f"  blob {c['sha'][:10]}" + ("  [PRESENT DANS HEAD]" if c.get("en_head") else "  [historique seul]")
                print(f"  [{c['sev']}] {loc}{tag}\n         {c['rule']}")
                if c.get("commit"):
                    print(f"         introduit : {c['commit']}")
                    if c.get("refs"):
                        print(f"         refs : {', '.join(c['refs'][:6])}" + (" …" if len(c["refs"]) > 6 else ""))
        print("\n== RESUME ==")
        print(f"  HAUT : {n_high}  |  MOYEN : {n_med}")
        if n_high:
            print("VERDICT : payload present dans l'historique. Un working tree propre ne suffit pas.\n"
                  "          Voir docs/prompt-nettoyage-depot.md (filter-repo + depot neuf). Ne JAMAIS executer un blob.")
        elif n_med:
            print("VERDICT : indicateurs faibles — inspecter avec `git cat-file -p <sha> | head -c 400 | cat -v`.")
        else:
            print("VERDICT : aucun indicateur PolinRider dans l'historique analyse.")
    sys.exit(2 if n_high else 1 if n_med else 0)


if __name__ == "__main__":
    main()
