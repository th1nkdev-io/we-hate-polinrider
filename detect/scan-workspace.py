#!/usr/bin/env python3
"""
scan-workspace.py — Scanner PolinRider multiplateforme (Linux / macOS / Windows).

LECTURE SEULE : ce script ne modifie, ne supprime et n'execute RIEN.
  - aucun sous-processus (pas meme `git` : l'historique est lu dans .git/logs) ;
  - aucun import / eval des fichiers scannes : ils sont lus comme des octets ;
  - les liens symboliques ne sont pas suivis.

Usage :
    python3 detect/scan-workspace.py                  # scanne ~/_Workspace
    python3 detect/scan-workspace.py /chemin/projets
    python3 detect/scan-workspace.py --deep           # inclut aussi le contenu de .git/
    python3 detect/scan-workspace.py --json > rapport.json

Code de sortie : 0 = rien, 1 = uniquement MOYEN, 2 = au moins un HAUT.

Detecte (voir docs/indicators-of-compromise.md) :
  - charge ajoutee en fin de fichier de config (postcss, tailwind, eslint, next, vite, ...)
    apres un bourrage d'espaces, lignes anormalement longues, taille anormale ;
  - marqueurs de la charge (signatures, decodeurs, globales, cles XOR, adresses crypto, UUID) ;
  - C2 Vercel (HAUT), domaines blockchain et IP C2 (MOYEN) ;
  - paquets npm pieges dans package.json / lockfiles / node_modules ;
  - fausses polices (verifiees par signature binaire, jamais par le nom) ;
  - fichiers IoC (temp_auto_push.bat, config.bat, branch_structure.json, spellright.dict) ;
  - .vscode/tasks.json et .vscode/settings.json auto-executants ; npm/lib/cli.js reecrit ;
  - commits amendes / horloge falsifiee dans le reflog git.

Script auditable : lisez-le avant de l'executer.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

HIGH, MED = "HAUT", "MOYEN"

# --------------------------------------------------------------------------- IoC
# Fichiers de config ciblés : la charge est ajoutée À LA FIN et s'exécute quand
# l'outil (PostCSS, ESLint, Vite, Next...) importe le module.
CONFIG_TARGETS = {
    "postcss.config.mjs", "postcss.config.js", "postcss.config.ts", "postcss.config.cjs",
    "tailwind.config.js", "tailwind.config.ts", "tailwind.config.mjs", "tailwind.config.cjs",
    "eslint.config.mjs", "eslint.config.js", "eslint.config.cjs", ".eslintrc.js", ".eslintrc.cjs",
    "next.config.mjs", "next.config.js", "next.config.ts",
    "vite.config.js", "vite.config.mjs", "vite.config.ts", "vite.config.cjs",
    "webpack.config.js", "webpack.config.mjs", "webpack.config.ts",
    "astro.config.mjs", "astro.config.js", "astro.config.ts",
    "nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs",
    "svelte.config.js", "rollup.config.js", "babel.config.js", "babel.config.cjs",
    "gridsome.config.js", "vue.config.js", "truffle.js", "truffle-config.js",
}
ENTRY_TARGETS = {"App.js", "app.js", "index.js"}

# Chaînes propres à la charge -> HAUT
HIGH_MARKERS = [
    ("signature v1", "rmcej%otb%"),
    ("signature v2", "Cot%3t=shtP"),
    ("decodeur v1", "_$_1e42"),
    ("decodeur v2", "MDy("),
    ("injection globale", "global['!']"),
    ("injection globale", 'global["!"]'),
    ("injection globale", "global['_V']"),
    ("injection globale", 'global["_V"]'),
    ("cle XOR", "2[gWfGj;<:-93Z^C"),
    ("cle XOR", "m6:tTh^D)cBz?NM]"),
    ("adresse TRON C2", "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"),
    ("adresse TRON C2", "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"),
    ("adresse Aptos C2", "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e"),
    ("adresse Aptos C2", "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"),
    ("UUID template StakingGame", "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"),
    ("id de campagne, variante global.i (sept. 2026)", "A10-*40840"),
    ("C2 Vercel", "default-configuration.vercel.app"),
    ("C2 Vercel", "260120.vercel.app"),
    ("C2 Vercel", "vscode-settings-bootstrap.vercel.app"),
    ("C2 Vercel", "vscode-settings-config.vercel.app"),
    ("C2 Vercel", "vscode-bootstrapper.vercel.app"),
    ("C2 Vercel", "vscode-load-config.vercel.app"),
]
HIGH_REGEXES = [
    ("variante global.i : global.i = 'A<n>-…' (id de campagne)",
     re.compile(rb"""global\.i\s*=\s*['"]A\d+-""")),
    ("tag de version de la charge (global['_V']='8-stN')",
     re.compile(rb"""global\[\s*['"]_V['"]\s*\]\s*=\s*['"]8-st\d+""")),
    ("URL C2 Vercel /settings/<os>?flag=",
     re.compile(rb"""\.vercel\.app/settings/(?:mac|linux|win)\b""")),
]
# Indicateurs parfois légitimes -> MOYEN
MED_MARKERS = [
    ("domaine blockchain (C2 possible)", "trongrid.io"),
    ("domaine blockchain (C2 possible)", "aptoslabs.com"),
    ("domaine blockchain (C2 possible)", "bsc-dataseed.binance.org"),
    ("domaine blockchain (C2 possible)", "bsc-rpc.publicnode"),
]
MED_REGEXES = [
    ("globale v1 courte global['r'] / global['m']",
     re.compile(rb"""global\[\s*['"][rm]['"]\s*\]\s*=""")),
    ("graine d'obfuscation connue",
     re.compile(rb"(?<!\d)(?:2857687|2667686|1111436|3896884)(?!\d)")),
]
C2_IPS = ["166.88.54.158", "198.105.127.210", "23.27.202.27", "154.91.0.103", "136.0.9.8",
          "166.88.4.2", "23.27.120.142", "202.155.8.173", "166.88.134.82", "188.43.33.249",
          "23.27.13.43"]
IP_RE = re.compile(rb"(?<![\d.])(" + b"|".join(re.escape(ip.encode()) for ip in C2_IPS) + rb")(?![\d.])")
# Exfiltration Telegram : suspect seulement dans un fichier de config / d'entrée
TELEGRAM = b"api.telegram.org"

BAD_PACKAGES = ["tailwindcss-style-animate", "tailwind-mainanimation", "tailwind-autoanimation",
                "tailwind-animationbased", "tailwindcss-typography-style", "tailwindcss-style-modify",
                "tailwindcss-animate-style"]
PKG_RE = re.compile(rb"(?<![\w@/.-])(" + b"|".join(re.escape(p.encode()) for p in BAD_PACKAGES) + rb")(?![\w-])")
PKG_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
             "pnpm-lock.yaml", "bun.lock"}

FONT_EXTS = {".woff2", ".woff", ".ttf", ".otf", ".eot"}
FONT_MAGICS = (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf")

EXCLUDED_DIRS = {"node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", ".output",
                 ".svelte-kit", ".vercel", ".turbo", ".cache", ".parcel-cache", ".angular",
                 "coverage", "__pycache__", ".venv", "venv", ".gradle", "Pods", "vendor", "target"}
CODE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".vue", ".svelte",
             ".astro", ".json", ".dict", ".bat", ".cmd", ".ps1", ".sh"} | FONT_EXTS

CODE_CHARS = re.compile(r"[;(){}=]|=>")   # un vide de 30-99 espaces n'est suspect que suivi de code
LEAD_PAD = 100      # espaces en tête de ligne
MID_PAD = 30        # espaces au milieu (code ... vide ... code)
LONG_LINE = 1000    # longueur de ligne anormale dans une config
BIG_CONFIG = 3000   # config saine ~80-200 o, infectée ~5000 o
PAD_RE = re.compile(r"\S([ \t]{%d,})\S" % MID_PAD)


# ------------------------------------------------------------------- utilitaires
class Report:
    def __init__(self):
        self.items = {}

    def add(self, sev, path, line, rule, detail=""):
        key = (str(path), line, rule)
        cur = self.items.get(key)
        if cur is None or (cur["sev"] == MED and sev == HIGH):
            self.items[key] = {"sev": sev, "path": str(path), "line": line,
                               "rule": rule, "detail": detail}

    def sorted(self):
        order = {HIGH: 0, MED: 1}
        return sorted(self.items.values(),
                      key=lambda f: (order[f["sev"]], f["path"], f["line"] or 0, f["rule"]))


def line_of(data, idx):
    return data.count(b"\n", 0, idx) + 1


def safe_preview(text, n=60):
    """Aperçu inoffensif (pas de caractères de contrôle, tronqué)."""
    text = text.strip()
    out = "".join(c if c.isprintable() else "?" for c in text[:n])
    return out + ("…" if len(text) > n else "")


def read_bytes(path, limit):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit + 1)
    except OSError:
        return None


# -------------------------------------------------------------------- contrôles
def is_guard(path):
    """Garde defensive (ex. .github/workflows/security-guard.yml) : elle CONTIENT les signatures
    qu'elle traque. Ses marqueurs sont rétrogradés en MOYEN, pas ignorés (un nom ne prouve rien)."""
    return "security-guard" in path.name.lower()


def check_strings(rep, path, data, sensitive):
    guard = is_guard(path)
    note = " [garde defensive probable : security-guard*, a relire, ne PAS supprimer d'office]"
    for label, needle in HIGH_MARKERS:
        i = data.find(needle.encode())
        if i != -1:
            rep.add(MED if guard else HIGH, path, line_of(data, i),
                    f"{label} : {needle}" + (note if guard else ""))
    for label, rx in HIGH_REGEXES:
        m = rx.search(data)
        if m:
            rep.add(MED if guard else HIGH, path, line_of(data, m.start()), label + (note if guard else ""))
    for label, needle in MED_MARKERS:
        i = data.find(needle.encode())
        if i != -1:
            rep.add(MED, path, line_of(data, i), f"{label} : {needle}")
    for label, rx in MED_REGEXES:
        m = rx.search(data)
        if m:
            rep.add(MED, path, line_of(data, m.start()), f"{label} : {m.group(0).decode(errors='replace')}")
    m = IP_RE.search(data)
    if m:
        rep.add(MED, path, line_of(data, m.start()), f"IP C2 connue : {m.group(1).decode()}")
    if sensitive:
        i = data.find(TELEGRAM)
        if i != -1:
            rep.add(MED, path, line_of(data, i), "API Telegram dans une config/entree (exfiltration ?)")


def is_comment(tail):
    """Vrai si la « queue » après le vide n'est qu'un commentaire (rien d'exécutable).
    `/*x*/ code` n'est PAS un commentaire : sinon un simple préfixe suffirait à échapper."""
    t = tail.strip()
    if t.startswith(("//", "#")) or (t.startswith("*") and not t.startswith("*/")):
        return True
    if t.startswith("/*"):
        end = t.find("*/", 2)
        return end == -1 or not t[end + 2:].strip(" ;")
    return False


def check_padding(rep, path, data, target, min_tail=20):
    """Bourrage d'espaces : ≥100 espaces en tête, ou ≥30 au milieu d'une ligne de code.
    target : fichier cible (config/entrée) -> HAUT dès que du code (≥ min_tail car.) suit le vide."""
    text = data.decode("utf-8", errors="replace")
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) < MID_PAD:
            continue
        stripped = line.lstrip(" \t")
        lead = len(line) - len(stripped)
        tail = None
        if lead >= LEAD_PAD and stripped:
            tail, kind, gap = stripped, "en tete", lead
        else:
            m = PAD_RE.search(line)
            if m:
                tail, kind, gap = line[m.end(1):], "au milieu", len(m.group(1))
        # Le vrai bourrage fait des centaines d'espaces. Un vide plus court suivi de texte sans code
        # (ASCII art, alignement dans un commentaire ou une chaîne) est un faux positif.
        if tail is not None and gap < LEAD_PAD and not CODE_CHARS.search(tail):
            tail = None
        if tail is not None and not is_comment(tail):
            if target and len(tail.strip()) >= min_tail:
                rep.add(HIGH, path, n, f"bourrage de {gap} espaces {kind} puis code "
                        f"({len(tail)} car.) — charge dissimulee", safe_preview(tail))
            elif len(tail.strip()) >= 100:
                rep.add(MED, path, n, f"bourrage de {gap} espaces {kind} puis {len(tail)} car. de code",
                        safe_preview(tail))
        if target and len(line) >= LONG_LINE:
            rep.add(HIGH, path, n, f"ligne de {len(line)} caracteres dans un fichier cible",
                    safe_preview(stripped))


def check_font(rep, path, data):
    ext = path.suffix.lower()
    if not data:
        return  # fichier vide : pas une charge
    if ext == ".eot":
        # EOT : pas de magic en tête ; MagicNumber 0x504C (little-endian) à l'offset 34.
        ok = len(data) >= 36 and data[34:36] == b"\x4c\x50"
    else:
        ok = data[:4] in FONT_MAGICS
    if not ok:
        what = "texte/JS deguise" if b"\x00" not in data[:512] else "signature inconnue"
        rep.add(HIGH, path, 1, f"fausse police {ext} (debut {data[:4]!r}, pas une police) — {what}")


def check_tasks_json(rep, path, data):
    low = data.lower()
    folder_open = b"folderopen" in low
    if folder_open:
        rep.add(HIGH, path, line_of(data, low.find(b"folderopen")), "tasks.json auto-executant (runOn: folderOpen)")
    m = re.search(rb'"command"\s*:\s*"[^"]*\bnode\b', data)
    if m:
        rep.add(HIGH if folder_open else MED, path, line_of(data, m.start()),
                "tasks.json lance node" + (" a l'ouverture du dossier" if folder_open else ""))
    m = re.search(rb"node\s+[^\s\"']+\.(?:woff2?|ttf|otf|eot|dict)\b", data)
    if m:
        rep.add(HIGH, path, line_of(data, m.start()), "tasks.json execute un fichier police/dict avec node")
    m = re.search(rb"(?:curl|wget)[^\n|]*\|\s*(?:ba|z)?sh\b", data)
    if m:
        rep.add(HIGH, path, line_of(data, m.start()), "tasks.json : curl|bash")


def check_settings_json(rep, path, data):
    """.vscode/settings.json : relance la charge a l'ouverture du dossier meme si tasks.json est supprime."""
    low = data.lower()
    if b"folderopen" in low:
        rep.add(HIGH, path, line_of(data, low.find(b"folderopen")),
                "settings.json contient une tache runOn: folderOpen (auto-execution)")
    else:
        m = re.search(rb'"task\.allowAutomaticTasks"\s*:\s*(?:true|"on")', data)
        if m:
            rep.add(MED, path, line_of(data, m.start()),
                    "task.allowAutomaticTasks actif : supprime le garde-fou de VS Code")


def check_ioc_file(rep, path, data):
    name = path.name
    if name == "temp_auto_push.bat":
        rep.add(HIGH, path, None, "fichier de propagation temp_auto_push.bat (fiabilite ~100 %)")
    elif name == "branch_structure.json":
        rep.add(HIGH, path, None, "branch_structure.json (depose par la charge)")
    elif name == "config.bat":
        rep.add(MED, path, None, "config.bat (artefact de propagation connu — lire le contenu)")
    elif name == "spellright.dict" and data is not None:
        m = re.search(rb"function\s*\(|=>|require\(|eval\(|global\[|\bconst\s|\bvar\s|;\s*\S", data)
        if m:
            rep.add(HIGH, path, line_of(data, m.start()), "spellright.dict contient du code")
    if data is not None and path.suffix.lower() in (".bat", ".cmd", ".sh", ".ps1"):
        if b"LAST_COMMIT_DATE" in data or (b"commit --amend" in data and b"push -uf" in data):
            rep.add(HIGH, path, None, "script de reecriture git (amend + push force, date d'origine conservee)")


def check_npm_cli(rep, path):
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > 20_000:
        rep.add(HIGH, path, None, f"npm/lib/cli.js reecrit : {size} octets (legitime : quelques centaines)")
    else:
        data = read_bytes(path, 20_000) or b""
        check_padding(rep, path, data, target=True)


def check_git_reflog(rep, gitdir):
    """Lit .git/logs (sans lancer git) : commits amendés et horloge qui recule."""
    logs = gitdir / "logs"
    if not logs.is_dir():
        return
    files = [logs / "HEAD"]
    if (logs / "refs" / "heads").is_dir():
        files += sorted((logs / "refs" / "heads").rglob("*"))
    for lf in files:
        if not lf.is_file():
            continue
        try:
            lines = lf.read_text("utf-8", errors="replace").splitlines()
        except OSError:
            continue
        amends, prev_ts = [], None
        for n, line in enumerate(lines, 1):
            head, _, msg = line.partition("\t")
            m = re.search(r"> (\d+) [+-]\d{4}$", head)
            ts = int(m.group(1)) if m else None
            if msg.startswith("commit (amend)"):
                amends.append(n)
            if ts is not None and prev_ts is not None and ts < prev_ts - 300:
                rep.add(MED, lf, n, "reflog : horodatage qui recule (horloge falsifiee avant amend ?)",
                        safe_preview(msg))
            if ts is not None:
                prev_ts = max(prev_ts or ts, ts)
        if amends:
            rep.add(MED, lf, amends[-1], f"reflog : {len(amends)} commit(s) amende(s) — verifier qu'ils sont de vous",
                    "lignes " + ", ".join(map(str, amends[-10:])))
    hooks = gitdir / "hooks"
    if hooks.is_dir():
        for h in hooks.iterdir():
            if h.is_file() and not h.name.endswith(".sample"):
                rep.add(MED, h, None, "hook git actif (non .sample) — a relire")


def npm_cli_candidates():
    """Emplacements de npm/lib/cli.js global, trouvés sans exécuter npm."""
    out = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for exe in ("npm", "npm.cmd"):
            p = Path(d) / exe
            if p.exists():
                for base in (p.resolve().parent, p.parent):
                    out.add(base.parent / "lib" / "cli.js")                       # .../npm/bin/npm -> .../npm/lib
                    out.add(base.parent / "lib" / "node_modules" / "npm" / "lib" / "cli.js")
                    out.add(base / "node_modules" / "npm" / "lib" / "cli.js")     # Windows
    home = Path.home()
    for pat in (".nvm/versions/node/*/lib/node_modules/npm/lib/cli.js",
                "AppData/Roaming/nvm/*/node_modules/npm/lib/cli.js"):
        out.update(home.glob(pat))
    for p in ("/usr/lib/node_modules/npm/lib/cli.js", "/usr/local/lib/node_modules/npm/lib/cli.js",
              "/opt/homebrew/lib/node_modules/npm/lib/cli.js",
              r"C:\Program Files\nodejs\node_modules\npm\lib\cli.js"):
        out.add(Path(p))
    return {p for p in out if p.is_file() and p.parts[-3:] == ("npm", "lib", "cli.js")}


# ------------------------------------------------------------------------ scan
def scan(root, deep, max_size, self_root):
    rep = Report()
    stats = {"fichiers": 0, "ignores_taille": 0, "depots_git": 0}

    def in_self(p):
        return self_root is not None and (p == self_root or self_root in p.parents)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        keep = []
        for name in dirnames:
            sub = d / name
            if sub.is_symlink():
                continue
            if name == ".git":
                stats["depots_git"] += 1
                check_git_reflog(rep, sub)
                if deep:
                    keep.append(name)
                continue
            if name == "node_modules":
                # on n'y descend pas, mais on regarde les paquets pieges installes et npm/lib/cli.js
                for pkg in BAD_PACKAGES:
                    if (sub / pkg).is_dir():
                        rep.add(HIGH, sub / pkg, None, f"paquet npm piege installe : {pkg}")
                cli = sub / "npm" / "lib" / "cli.js"
                if cli.is_file():
                    check_npm_cli(rep, cli)
                continue
            if name in EXCLUDED_DIRS:
                continue
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            p = d / name
            if p.is_symlink():
                continue
            stats["fichiers"] += 1
            try:
                size = p.stat().st_size
            except OSError:
                continue
            ext = p.suffix.lower()
            is_target = name in CONFIG_TARGETS
            is_entry = name in ENTRY_TARGETS
            is_font = ext in FONT_EXTS
            is_tasks = name == "tasks.json" and d.name == ".vscode"
            is_settings = name == "settings.json" and d.name == ".vscode"

            if size > max_size and not is_font:
                stats["ignores_taille"] += 1
                if is_target or is_entry:
                    rep.add(HIGH, p, None, f"fichier cible de {size} octets (trop gros pour une config)")
                continue
            data = read_bytes(p, max_size if not is_font else 4096)
            if data is None:
                continue

            if not in_self(p):
                check_ioc_file(rep, p, data)
            if is_font:
                check_font(rep, p, data)
                if size > 4096:
                    data = read_bytes(p, max_size) or data
            if b"\x00" in data[:8192] and not is_font:
                continue  # binaire

            if not in_self(p):
                check_strings(rep, p, data, sensitive=is_target or is_entry or is_tasks or is_settings)
            if name in PKG_FILES:
                for m in PKG_RE.finditer(data):
                    rep.add(HIGH, p, line_of(data, m.start()), f"paquet npm piege : {m.group(1).decode()}")
            if is_tasks:
                check_tasks_json(rep, p, data)
            if is_settings:
                check_settings_json(rep, p, data)
            if is_target and size >= BIG_CONFIG:
                rep.add(MED, p, None, f"config de {size} octets (saine ~80-200, infectee ~5000) — a relire")
            if ext in CODE_EXTS and not name.endswith((".min.js", ".min.mjs")) and name not in PKG_FILES:
                # App.js/index.js sont très courants : on exige une « queue » de code plus longue
                check_padding(rep, p, data, target=is_target or is_entry, min_tail=20 if is_target else 100)

    for cli in npm_cli_candidates():
        check_npm_cli(rep, cli)
    return rep, stats


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description="Scanner PolinRider (lecture seule).")
    ap.add_argument("root", nargs="?", default=str(Path.home() / "_Workspace"),
                    help="dossier a scanner (defaut : ~/_Workspace)")
    ap.add_argument("--deep", action="store_true", help="scanner aussi le contenu des dossiers .git")
    ap.add_argument("--max-size", type=int, default=5_000_000, help="taille max lue par fichier (octets)")
    ap.add_argument("--json", action="store_true", help="sortie JSON")
    ap.add_argument("--include-self", action="store_true",
                    help="ne pas ignorer les marqueurs cites dans cette boite a outils")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        sys.exit(f"Dossier introuvable : {root}")
    self_root = Path(__file__).resolve().parent.parent
    if args.include_self or not (self_root / "docs" / "indicators-of-compromise.md").is_file():
        self_root = None

    rep, stats = scan(root, args.deep, args.max_size, self_root)
    findings = rep.sorted()
    n_high = sum(f["sev"] == HIGH for f in findings)
    n_med = len(findings) - n_high

    if args.json:
        json.dump({"racine": str(root), "stats": stats, "haut": n_high, "moyen": n_med,
                   "constats": findings}, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print(f"### SCAN POLINRIDER (lecture seule) — {root}" + ("  [--deep]" if args.deep else ""))
        if self_root and (self_root == root or root in self_root.parents):
            print(f"(marqueurs cites dans la boite a outils ignores : {self_root})")
        for sev in (HIGH, MED):
            group = [f for f in findings if f["sev"] == sev]
            if not group:
                continue
            print(f"\n== {sev} ({len(group)}) ==")
            for f in group:
                try:
                    shown = str(Path(f["path"]).relative_to(root))
                except ValueError:
                    shown = f["path"]
                loc = shown + (f":{f['line']}" if f["line"] else "")
                print(f"  [{sev}] {loc}\n         {f['rule']}")
                if f["detail"]:
                    print(f"         > {f['detail']}")
        print("\n== RESUME ==")
        print(f"  fichiers examines : {stats['fichiers']}  |  depots git : {stats['depots_git']}"
              f"  |  ignores (> {args.max_size} o) : {stats['ignores_taille']}")
        print(f"  HAUT : {n_high}  |  MOYEN : {n_med}")
        if n_high:
            print("VERDICT : INDICATEURS FORTS — considerer la machine et les depots comme compromis.\n"
                  "          NE PAS lancer npm/eslint/vite/next sur ces depots. Voir docs/playbook.md.")
        elif n_med:
            print("VERDICT : indicateurs faibles — lire chaque fichier signale avant de conclure.")
        else:
            print("VERDICT : aucun indicateur PolinRider trouve.")
    sys.exit(2 if n_high else 1 if n_med else 0)


if __name__ == "__main__":
    main()
