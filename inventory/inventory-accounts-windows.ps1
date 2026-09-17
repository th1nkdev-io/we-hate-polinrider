# =====================================================================
#  Inventaire des comptes et secrets presents sur ce PC
#  Detecteur d'inventaire — reponse a incident PolinRider (lecture seule)
#
#  AUCUN MOT DE PASSE N'EST LU NI AFFICHE. Le script liste uniquement :
#  sites, identifiants, domaines de cookies, noms de fichiers,
#  noms de variables. Le resultat peut etre partage sans risque.
#
#  A lancer sur le PC Windows, PowerShell EN ADMINISTRATEUR.
#  Il ferme Edge / Chrome / Firefox pour pouvoir lire leurs bases.
# =====================================================================

$out = "$env:USERPROFILE\Desktop\inventaire-comptes.txt"
$tmp = Join-Path $env:TEMP "inv-polinrider"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
"### INVENTAIRE $(Get-Date) - $env:COMPUTERNAME\$env:USERNAME" | Set-Content $out -Encoding UTF8
function T($s){ "`n=== $s ===" | Add-Content $out -Encoding UTF8 }
function L($s){ if ($null -ne $s) { $s | Add-Content $out -Encoding UTF8 } }

# Fermer les navigateurs (leurs bases sont verrouillees sinon)
"msedge","chrome","firefox","brave" | ForEach-Object {
  Get-Process $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

# Python disponible ? (permet une lecture propre des bases SQLite)
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }

$pyScript = @'
import sqlite3, sys
mode, path = sys.argv[1], sys.argv[2]
con = sqlite3.connect(path); cur = con.cursor(); seen = set()
try:
    if mode == "logins":
        for url, user in cur.execute("select origin_url, username_value from logins"):
            host = url.split('/')[2] if '://' in url else url
            k = (host, user)
            if k not in seen: seen.add(k); print(f"{host}\t{user}")
    elif mode == "cookies_chromium":
        for (h,) in cur.execute("select distinct host_key from cookies"): print(h.lstrip('.'))
    elif mode == "cookies_firefox":
        for (h,) in cur.execute("select distinct host from moz_cookies"): print(h.lstrip('.'))
except Exception as e:
    print(f"(erreur lecture: {e})")
'@
$pyFile = Join-Path $tmp "inv.py"
Set-Content $pyFile $pyScript -Encoding ASCII

function Read-Sqlite($mode, $file) {
  if (-not (Test-Path $file)) { return }
  $copy = Join-Path $tmp ([IO.Path]::GetRandomFileName())
  Copy-Item $file $copy -Force -ErrorAction SilentlyContinue
  if (-not (Test-Path $copy)) { return "(fichier verrouille, navigateur encore ouvert ?)" }
  if ($py) {
    & $py.Source $pyFile $mode $copy 2>$null | Sort-Object -Unique
  } else {
    # Repli sans Python : extraction approximative des URL dans le fichier brut
    $txt = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($copy))
    [regex]::Matches($txt, 'https?://[A-Za-z0-9.-]+') | ForEach-Object { $_.Value -replace '^https?://','' } | Sort-Object -Unique
  }
  Remove-Item $copy -Force -ErrorAction SilentlyContinue
}

# ---------- Navigateurs Chromium (Edge, Chrome, Brave) ----------
$chromiums = [ordered]@{
  "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
  "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
  "Brave"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
}
foreach ($b in $chromiums.Keys) {
  $root = $chromiums[$b]
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem $root -Directory | Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" } | ForEach-Object {
    $p = $_.FullName
    T "$b / $($_.Name) - sites avec mot de passe enregistre  (site <tab> identifiant)"
    L (Read-Sqlite "logins" "$p\Login Data")
    T "$b / $($_.Name) - domaines avec cookies (sessions ouvertes)"
    L (Read-Sqlite "cookies_chromium" "$p\Network\Cookies")
    T "$b / $($_.Name) - extensions installees"
    Get-ChildItem "$p\Extensions" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $m = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Select-Object -First 1
      $name = ""
      if ($m) { try { $name = (Get-Content $m.FullName -Raw | ConvertFrom-Json).name } catch {} }
      L "$($_.Name)  $name"
    }
  }
}

# ---------- Firefox ----------
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  $p = $_.FullName
  $lj = "$p\logins.json"
  if (Test-Path $lj) {
    T "Firefox / $($_.Name) - sites avec mot de passe enregistre"
    try { L ((Get-Content $lj -Raw | ConvertFrom-Json).logins | ForEach-Object { $_.hostname } | Sort-Object -Unique) } catch { L "(illisible)" }
  }
  if (Test-Path "$p\cookies.sqlite") {
    T "Firefox / $($_.Name) - domaines avec cookies (sessions ouvertes)"
    L (Read-Sqlite "cookies_firefox" "$p\cookies.sqlite")
  }
  if (Test-Path "$p\extensions.json") {
    T "Firefox / $($_.Name) - extensions installees"
    try { L ((Get-Content "$p\extensions.json" -Raw | ConvertFrom-Json).addons | Where-Object { $_.type -eq "extension" } | ForEach-Object { "$($_.id)  $($_.defaultLocale.name)" }) } catch {}
  }
}

# ---------- Gestionnaire d'identifiants Windows (noms seulement) ----------
T "Windows Credential Manager - identifiants generiques (cibles)"
L (cmdkey /list 2>$null | Select-String "Cible|Target" | ForEach-Object { $_.Line.Trim() })
T "Windows Credential Manager - identifiants web (ressources)"
L (vaultcmd /listcreds:"Informations d'identification Web" /all 2>$null | Select-String "Ressource|Resource" | ForEach-Object { $_.Line.Trim() })
L (vaultcmd /listcreds:"Web Credentials" /all 2>$null | Select-String "Ressource|Resource" | ForEach-Object { $_.Line.Trim() })

# ---------- Fichiers et dossiers de secrets presents ----------
T "Fichiers / dossiers de configuration contenant des secrets (presence seulement)"
@(
  "$env:USERPROFILE\.ssh", "$env:USERPROFILE\.npmrc", "$env:USERPROFILE\.yarnrc.yml", "$env:USERPROFILE\.bunfig.toml",
  "$env:USERPROFILE\.gitconfig", "$env:USERPROFILE\.git-credentials", "$env:USERPROFILE\.netrc",
  "$env:USERPROFILE\.config\gh\hosts.yml", "$env:APPDATA\GitHub Desktop",
  "$env:USERPROFILE\.aws", "$env:USERPROFILE\.azure", "$env:USERPROFILE\.config\gcloud", "$env:USERPROFILE\.kube",
  "$env:USERPROFILE\.docker\config.json", "$env:USERPROFILE\.composer\auth.json", "$env:USERPROFILE\.pypirc",
  "$env:USERPROFILE\.cargo\credentials.toml", "$env:USERPROFILE\.expo", "$env:USERPROFILE\.vercel", "$env:USERPROFILE\.netlify",
  "$env:USERPROFILE\.keystores", "$env:USERPROFILE\.android", "$env:USERPROFILE\.gradle\gradle.properties",
  "$env:USERPROFILE\.aider", "$env:USERPROFILE\.codex", "$env:USERPROFILE\.continue", "$env:USERPROFILE\.copilot",
  "$env:USERPROFILE\.cursor", "$env:USERPROFILE\.codeium", "$env:USERPROFILE\.claude", "$env:USERPROFILE\.wakatime.cfg",
  "$env:APPDATA\Postman", "$env:APPDATA\Code\User\settings.json", "$env:USERPROFILE\.wallaby", "$env:USERPROFILE\.quokka"
) | ForEach-Object { if (Test-Path $_) { L "PRESENT  $_" } }

# ---------- Cles SSH ----------
T "Cles SSH (nom + empreinte) - a comparer avec GitHub et les VPS"
Get-ChildItem "$env:USERPROFILE\.ssh" -File -ErrorAction SilentlyContinue | ForEach-Object { L "  $($_.Name)  ($($_.LastWriteTime.ToString('yyyy-MM-dd')))" }
Get-ChildItem "$env:USERPROFILE\.ssh\*.pub" -ErrorAction SilentlyContinue | ForEach-Object { L "$($_.Name) : $(ssh-keygen -lf $_.FullName 2>$null)" }
if (Test-Path "$env:USERPROFILE\.ssh\config") {
  L "--- hotes dans .ssh\config ---"
  L (Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '^\s*(Host|HostName|User)\s' | ForEach-Object { $_.Line.Trim() })
}

# ---------- Extensions VS Code / Cursor ----------
T "Extensions VS Code / Cursor (nom + date)"
Get-ChildItem "$env:USERPROFILE\.vscode\extensions", "$env:USERPROFILE\.cursor\extensions" -Directory -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | ForEach-Object { L "$($_.LastWriteTime.ToString('yyyy-MM-dd'))  $($_.Name)" }

# ---------- Fichiers .env : NOMS de variables uniquement ----------
$roots = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\source",
           "$env:USERPROFILE\Projects", "$env:USERPROFILE\dev", "$env:USERPROFILE\Downloads", "C:\dev", "C:\projects") |
  Where-Object { Test-Path $_ }
T "Fichiers .env dans les projets - noms de variables (les valeurs ne sont PAS lues)"
Get-ChildItem $roots -Recurse -Force -Include ".env", ".env.*" -File -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.Name -notmatch 'example|sample|template|dist' } | ForEach-Object {
    L "--- $($_.FullName)  ($($_.LastWriteTime.ToString('yyyy-MM-dd')))"
    Get-Content $_.FullName -ErrorAction SilentlyContinue |
      Where-Object { $_ -match '^\s*[A-Za-z_][A-Za-z0-9_]*\s*=' -and $_ -notmatch '^\s*#' } |
      ForEach-Object { ($_ -split '=',2)[0].Trim() } | Sort-Object -Unique | ForEach-Object { L "    $_" }
}

# ---------- Depots git locaux ----------
T "Depots git locaux et remotes (perimetre GitHub)"
Get-ChildItem $roots -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '\\node_modules\\' } | ForEach-Object {
    $d = $_.Parent.FullName
    $r = (git -C $d config --get remote.origin.url 2>$null)
    L "$d -> $r"
}

# ---------- Wi-Fi ----------
T "Reseaux Wi-Fi enregistres (noms)"
L ((netsh wlan show profiles 2>$null) | Select-String ":" | ForEach-Object { ($_ -split ':',2)[1].Trim() } | Where-Object { $_ })

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
L "`n### FIN"
Write-Host "`nInventaire ecrit dans : $out" -ForegroundColor Green
notepad $out
