<#
  detect-polinrider-windows.ps1
  Detecteur PolinRider pour Windows - LECTURE SEULE (ne supprime/modifie/execute rien).
  N'execute AUCUN fichier scanne, ne lance ni git ni npm : les fichiers sont lus comme des octets.
  Usage : PowerShell (admin conseille pour voir tous les processus), puis :
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\detect-polinrider-windows.ps1                       # profil + tous les lecteurs
      .\detect-polinrider-windows.ps1 -Roots C:\Users\moi\_Workspace
  Resultat : un rapport sur le Bureau (detect-polinrider.txt) + verdict a l'ecran.
    [!] HAUT  = indicateur fort (machine/depot a considerer comme compromis)
    [?] MOYEN = parfois legitime : lire le fichier avant de conclure
  Analyse plus fine (fichier:ligne) : python detect\scan-workspace.py
  Compatible Windows PowerShell 5.1. Script auditable : lisez-le avant de l'executer.
#>
param([string[]]$Roots)

$out = "$env:USERPROFILE\Desktop\detect-polinrider.txt"
if (-not $Roots) {
  $Roots = @("$env:USERPROFILE") + (Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -gt 0} | ForEach-Object {$_.Root})
}
$Roots = $Roots | Select-Object -Unique
"### DETECTION POLINRIDER - $(Get-Date) - $env:COMPUTERNAME\$env:USERNAME - cibles: $($Roots -join ', ')" | Set-Content $out -Encoding UTF8
$script:flag = $false; $script:warn = $false
function Hit($msg){ $script:flag=$true; "  [!] HAUT  $msg" | Tee-Object -FilePath $out -Append }
function Warn($msg){ $script:warn=$true; "  [?] MOYEN $msg" | Tee-Object -FilePath $out -Append }
function Section($t){ "`n== $t ==" | Tee-Object -FilePath $out -Append }

# Boite a outils elle-meme (elle CITE les marqueurs) : ses resultats textuels sont ignores.
$selfRoot = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path (Join-Path $selfRoot 'docs\indicators-of-compromise.md'))) { $selfRoot = $null }

# ------------------------------------------------------------------------ IoC
# Configs ciblees : charge AJOUTEE A LA FIN apres ~280 espaces, executee a l'import.
# postcss.config.mjs = cible n1 (~62 %).
$targets = @('postcss.config.mjs','postcss.config.js','postcss.config.ts','postcss.config.cjs',
  'tailwind.config.js','tailwind.config.ts','tailwind.config.mjs','tailwind.config.cjs',
  'eslint.config.mjs','eslint.config.js','eslint.config.cjs','.eslintrc.js','.eslintrc.cjs',
  'next.config.mjs','next.config.js','next.config.ts',
  'vite.config.js','vite.config.mjs','vite.config.ts','vite.config.cjs',
  'webpack.config.js','webpack.config.mjs','webpack.config.ts',
  'astro.config.mjs','astro.config.js','astro.config.ts','nuxt.config.ts','nuxt.config.js','nuxt.config.mjs',
  'svelte.config.js','rollup.config.js','babel.config.js','babel.config.cjs',
  'gridsome.config.js','vue.config.js','truffle.js','truffle-config.js')
$entries = @('App.js','app.js','index.js')
$highMarkers = @(
  'rmcej%otb%','Cot%3t=shtP',                       # signatures v1 / v2
  '_$_1e42','MDy(',                                 # decodeurs v1 / v2
  "global['!']","global['_V']",'global["!"]','global["_V"]',
  '2[gWfGj;<:-93Z^C','m6:tTh^D)cBz?NM]',            # cles XOR
  'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP','TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG',   # TRON
  '0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e',        # Aptos
  '0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3',        # Aptos
  'e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9',           # UUID template StakingGame
  'A10-*40840',                                     # id de campagne, variante « global.i » (sept. 2026)
  'default-configuration.vercel.app','260120.vercel.app',
  'vscode-settings-bootstrap.vercel.app','vscode-settings-config.vercel.app',
  'vscode-bootstrapper.vercel.app','vscode-load-config.vercel.app')
$highRegex = @{
  "tag de version global['_V']='8-stN'" = "global\[['""]_V['""]\]\s*=\s*['""]8-st\d+"
  'URL C2 Vercel /settings/<os>'         = '\.vercel\.app/settings/(mac|linux|win)\b'
}
$medMarkers = @('trongrid.io','aptoslabs.com','bsc-dataseed.binance.org','bsc-rpc.publicnode')
$c2Ips = '(?<![\d.])(166\.88\.54\.158|198\.105\.127\.210|23\.27\.202\.27|154\.91\.0\.103|136\.0\.9\.8|166\.88\.4\.2|23\.27\.120\.142|202\.155\.8\.173|166\.88\.134\.82|188\.43\.33\.249|23\.27\.13\.43)(?![\d.])'
$badPkgs = @('tailwindcss-style-animate','tailwind-mainanimation','tailwind-autoanimation','tailwind-animationbased',
  'tailwindcss-typography-style','tailwindcss-style-modify','tailwindcss-animate-style')
$pkgRegex = '(?<![\w@/.-])(' + (($badPkgs | ForEach-Object {[regex]::Escape($_)}) -join '|') + ')(?![\w-])'
$pkgFiles = @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','bun.lock')
$fontExts = @('.woff2','.woff','.ttf','.otf','.eot')
$fontMagics = @('wOF2','wOFF',"$([char]0)$([char]1)$([char]0)$([char]0)",'OTTO','true','ttcf')
$textExts = @('.js','.mjs','.cjs','.ts','.mts','.cts','.jsx','.tsx','.vue','.svelte','.astro','.json',
  '.dict','.bat','.cmd','.ps1','.sh','.yaml','.yml','.lock','.txt','.html','.env') + $fontExts
$excl = @('node_modules','.git','dist','build','out','.next','.nuxt','.output','.svelte-kit','.vercel','.turbo',
  '.cache','.parcel-cache','.angular','coverage','__pycache__','.venv','venv','.gradle','vendor','target','$Recycle.Bin')
$skip = '\\AppData\\Local\\(Temp|Microsoft)|\\Windows\\|\\Program Files|\\ProgramData\\'
$maxSize = 5MB
$latin1 = [Text.Encoding]::GetEncoding(28591)   # 1 octet = 1 caractere : lecture brute, sans interpretation

# ------------------------------------------------------ parcours unique du disque
# (un seul parcours, qui ne descend PAS dans node_modules/.git/build : bien plus rapide)
$files = New-Object System.Collections.Generic.List[string]
$nodeModules = New-Object System.Collections.Generic.List[string]
$gitDirs = New-Object System.Collections.Generic.List[string]
$stack = New-Object System.Collections.Stack
foreach ($r in $Roots) { if (Test-Path -LiteralPath $r) { $stack.Push((Resolve-Path -LiteralPath $r).ProviderPath) } }
$seen = @{}
while ($stack.Count -gt 0) {
  $d = $stack.Pop()
  if ($seen.ContainsKey($d)) { continue }; $seen[$d] = $true
  try { foreach ($f in [IO.Directory]::EnumerateFiles($d)) { $files.Add($f) } } catch {}
  try {
    foreach ($s in [IO.Directory]::EnumerateDirectories($d)) {
      $n = [IO.Path]::GetFileName($s)
      if ($n -eq 'node_modules') { $nodeModules.Add($s); continue }
      if ($n -eq '.git') { $gitDirs.Add($s); continue }
      if ($excl -contains $n -or $s -match $skip) { continue }
      try { if ([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint) { continue } } catch { continue }
      $stack.Push($s)
    }
  } catch {}
}
"  fichiers parcourus : $($files.Count) | node_modules : $($nodeModules.Count) | depots git : $($gitDirs.Count)" | Add-Content $out

function InSelf($p){ return ($selfRoot -and $p.StartsWith($selfRoot + '\', [StringComparison]::OrdinalIgnoreCase)) }
function LineOf($text, $idx){ return ([regex]::Matches($text.Substring(0, $idx), "`n")).Count + 1 }
function ReadText($p){ try { return $latin1.GetString([IO.File]::ReadAllBytes($p)) } catch { return $null } }
function ReadHead($p, $n){
  try { $fs=[IO.File]::OpenRead($p); $buf=New-Object byte[] $n; $k=$fs.Read($buf,0,$n); $fs.Close()
        return $buf[0..([Math]::Max($k-1,0))] } catch { return @() }
}
# Commentaire pur ? ("/*x*/ code" = du code : sinon un simple prefixe suffirait a echapper)
function IsComment($t){
  $t = $t.Trim()
  if ($t.StartsWith('//') -or $t.StartsWith('#') -or ($t.StartsWith('*') -and -not $t.StartsWith('*/'))) { return $true }
  if ($t.StartsWith('/*')) { $e = $t.IndexOf('*/', 2); if ($e -lt 0) { return $true }; return ($t.Substring($e+2).Trim(' ',';') -eq '') }
  return $false
}
# Bourrage : >=100 espaces en tete ou >=30 au milieu, suivi de code ; ligne >= 1000 car.
function Test-Padding($p, $text, $minTail, $checkLong){
  $n = 0; $found = 0
  foreach ($line in ($text -split "`n")) {
    $n++; $l = $line.TrimEnd("`r").Replace("`t", ' ')
    if ($l.Length -lt 30) { continue }
    $body = $l.TrimStart(' '); $lead = $l.Length - $body.Length; $tail = $null; $kind = ''
    if ($lead -ge 100 -and $body.Length -gt 0) { $tail = $body; $kind = "$lead espaces en tete" }
    elseif ($l -match '\S( {30,})(\S.*)$') { $tail = $Matches[2]; $kind = "vide de $($Matches[1].Length) espaces au milieu" }
    if ($tail -and $tail.Trim().Length -ge $minTail -and -not (IsComment $tail)) {
      Hit "charge dissimulee : ${p}:$n : $kind puis $($tail.Length) car. de code"; $found++
    }
    if ($checkLong -and $l.Length -ge 1000) { Hit "ligne de $($l.Length) caracteres : ${p}:$n"; $found++ }
    if ($found -ge 3) { break }
  }
}

# ------------------------------------------------------------------ controles
Section "1. Fichiers de propagation / leurres (temp_auto_push.bat, config.bat, branch_structure.json, spellright.dict)"
foreach ($f in $files) {
  $name = [IO.Path]::GetFileName($f)
  switch -CaseSensitive ($name) {
    'temp_auto_push.bat'    { Hit "temp_auto_push.bat (fiabilite ~100%) : $f" }
    'branch_structure.json' { Hit "branch_structure.json : $f" }
    'config.bat' {
      if (Select-String -LiteralPath $f -Pattern 'LAST_COMMIT_DATE|commit --amend' -Quiet -ErrorAction SilentlyContinue) { Hit "config.bat reecrit l'historique git : $f" }
      else { Warn "config.bat (a relire) : $f" } }
    'spellright.dict' {
      if (Select-String -LiteralPath $f -Pattern 'function\s*\(|=>|require\(|eval\(|global\[|\b(const|var)\s' -Quiet -ErrorAction SilentlyContinue) { Hit "spellright.dict contient du code : $f" } }
  }
}

Section "2. Configs ciblees (postcss n1, tailwind, eslint, next, vite, webpack, astro, nuxt...) + App.js/index.js"
foreach ($f in $files) {
  $name = [IO.Path]::GetFileName($f)
  $isTarget = $targets -ccontains $name; $isEntry = $entries -ccontains $name
  if (-not ($isTarget -or $isEntry)) { continue }
  $size = (New-Object IO.FileInfo $f).Length
  if ($size -gt $maxSize) { Hit "fichier cible de $size octets : $f"; continue }
  $text = ReadText $f; if ($null -eq $text) { continue }
  if ($isTarget) {
    Test-Padding $f $text 20 $true
    if ($size -ge 3000) { Warn "config de $size octets (saine ~80-200, infectee ~5000) : $f" }
  } else {
    Test-Padding $f $text 100 $false   # App.js/index.js : tres courants -> queue de code plus longue
  }
}

Section "3-4. Marqueurs de la charge (HAUT) / domaines blockchain et IP C2 (MOYEN)"
foreach ($f in $files) {
  if ($f -eq $out -or (InSelf $f)) { continue }
  $ext = [IO.Path]::GetExtension($f).ToLower(); $name = [IO.Path]::GetFileName($f)
  if (-not ($textExts -contains $ext -or $pkgFiles -contains $name)) { continue }
  if ((New-Object IO.FileInfo $f).Length -gt $maxSize) { continue }
  $text = ReadText $f; if ($null -eq $text) { continue }
  foreach ($m in $highMarkers) {
    $i = $text.IndexOf($m, [StringComparison]::Ordinal)
    if ($i -ge 0) { Hit "marqueur '$m' : ${f}:$(LineOf $text $i)" }
  }
  foreach ($k in $highRegex.Keys) {
    $mm = [regex]::Match($text, $highRegex[$k]); if ($mm.Success) { Hit "$k : ${f}:$(LineOf $text $mm.Index)" }
  }
  foreach ($m in $medMarkers) {
    $i = $text.IndexOf($m, [StringComparison]::Ordinal)
    if ($i -ge 0) { Warn "domaine blockchain '$m' : ${f}:$(LineOf $text $i)" }
  }
  $mm = [regex]::Match($text, $c2Ips); if ($mm.Success) { Warn "IP C2 connue $($mm.Value) : ${f}:$(LineOf $text $mm.Index)" }
  if ($pkgFiles -contains $name) {
    foreach ($pm in [regex]::Matches($text, $pkgRegex)) { Hit "paquet npm piege '$($pm.Value)' : ${f}:$(LineOf $text $pm.Index)" }
  }
}

Section "5. Paquets npm pieges installes (node_modules)"
foreach ($nm in $nodeModules) {
  foreach ($p in $badPkgs) { if (Test-Path -LiteralPath (Join-Path $nm $p)) { Hit "paquet piege installe : $(Join-Path $nm $p)" } }
}

Section "6. Fausses polices .woff2/.woff/.ttf/.otf/.eot (signature binaire, JAMAIS le nom)"
foreach ($f in $files) {
  $ext = [IO.Path]::GetExtension($f).ToLower()
  if ($fontExts -notcontains $ext) { continue }
  $b = ReadHead $f 36
  if ((New-Object IO.FileInfo $f).Length -eq 0) { continue }   # fichier vide : pas une charge
  if ($ext -eq '.eot') { $ok = ($b.Count -ge 36 -and $b[34] -eq 0x4C -and $b[35] -eq 0x50) }
  else { $sig = if ($b.Count -ge 4) { $latin1.GetString([byte[]]$b[0..3]) } else { '' }; $ok = $fontMagics -ccontains $sig }
  if (-not $ok) {
    $hex = ($b | Select-Object -First 4 | ForEach-Object { $_.ToString('x2') }) -join ''
    Hit "fausse police (octets '$hex', pas une police) : $f"
  }
}

Section "7. .vscode/tasks.json auto-executant"
foreach ($f in $files) {
  if ($f -notmatch '\\\.vscode\\tasks\.json$') { continue }
  $t = ReadText $f; if ($null -eq $t) { continue }
  $fo = $t -match 'folderOpen'
  if ($fo) { Hit "tasks.json auto-executant (runOn: folderOpen) : $f" }
  if ($t -match 'node\s+[^\s"'']+\.(woff2?|ttf|otf|eot|dict)\b') { Hit "tasks.json execute une police/dict avec node : $f" }
  if ($t -match '(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b') { Hit "tasks.json curl|bash : $f" }
  if ($t -match '"command"\s*:\s*"[^"]*\bnode\b') { if ($fo) { Hit "tasks.json lance node a l'ouverture : $f" } else { Warn "tasks.json lance node : $f" } }
}

Section "7b. .vscode\settings.json (task.allowAutomaticTasks + tasks folderOpen)"
foreach ($f in $files) {
  if ($f -notmatch '\\\.vscode\\settings\.json$') { continue }
  $t = ReadText $f; if ($null -eq $t) { continue }
  if ($t -match 'folderOpen') { Hit "settings.json contient une tache runOn: folderOpen : $f" }
  elseif ($t -match '"task\.allowAutomaticTasks"\s*:\s*(true|"on")') { Warn "settings.json : task.allowAutomaticTasks actif (supprime le garde-fou de VS Code) : $f" }
}

Section "8. npm\lib\cli.js global (reecrit : ~1 Mo au lieu de quelques centaines d'octets)"
$cands = @("$env:ProgramFiles\nodejs\node_modules\npm\lib\cli.js", "$env:APPDATA\npm\node_modules\npm\lib\cli.js")
$npmCmd = Get-Command npm -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1   # localise, n'execute pas
if ($npmCmd) { $cands += Join-Path (Split-Path $npmCmd.Source) 'node_modules\npm\lib\cli.js' }
$cands += Get-ChildItem "$env:APPDATA\nvm\*\node_modules\npm\lib\cli.js" -ErrorAction SilentlyContinue | ForEach-Object FullName
foreach ($c in ($cands | Select-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $c)) { continue }
  $s = (Get-Item -LiteralPath $c).Length; "  npm cli.js : $c ($s octets)" | Add-Content $out
  if ($s -gt 20000) { Hit "npm/lib/cli.js reecrit ($s octets) : $c" }
}

Section "9. Historique git : commits amendes / horloge qui recule (lecture de .git\logs, git n'est PAS lance)"
foreach ($g in $gitDirs) {
  $lf = Join-Path $g 'logs\HEAD'; if (-not (Test-Path -LiteralPath $lf)) { continue }
  $lines = Get-Content -LiteralPath $lf -ErrorAction SilentlyContinue
  $amend = @($lines | Where-Object { $_ -match "`tcommit \(amend\)" }).Count
  if ($amend -gt 0) { Warn "$amend commit(s) amende(s) dans le reflog : $(Split-Path $g)" }
  $prev = 0; $n = 0
  foreach ($l in $lines) { $n++
    if ($l -match '> (\d+) [+-]\d{4}\t') { $t = [long]$Matches[1]
      if ($prev -gt 0 -and $t -lt ($prev - 300)) { Warn "reflog : horodatage qui recule (ligne $n, horloge falsifiee ?) : $lf"; break }
      if ($t -gt $prev) { $prev = $t } }
  }
  Get-ChildItem -LiteralPath (Join-Path $g 'hooks') -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike '*.sample' } | ForEach-Object { Warn "hook git actif (a relire) : $($_.FullName)" }
}

Section "10. Processus node suspects en cours (node -e / --eval)"
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
  Where-Object {$_.CommandLine -match '\s(-e|--eval)\s'} | ForEach-Object { Hit "process PID $($_.ProcessId) : $($_.CommandLine)" }

Section "11. Persistance (cles Run, taches planifiees) et detections Defender"
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue |
  ForEach-Object { $_.PSObject.Properties | Where-Object {$_.Value -match 'node|\.js|powershell -enc|curl|wget'} | ForEach-Object { Hit "Run: $($_.Name) = $($_.Value)" } }
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
  $tn = $_.TaskPath + $_.TaskName
  foreach ($a in $_.Actions) { if ("$($a.Execute) $($a.Arguments)" -match 'node(\.exe)?\s|\.js\b|powershell.*-enc|wscript|curl|wget') { Warn "tache planifiee '$tn' : $($a.Execute) $($a.Arguments)" } }
}
Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {
  $th = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue
  if ($th.ThreatName -match 'PolinRider') { Hit "Defender a detecte $($th.ThreatName) : $($_.Resources -join ', ')" }
}

"`n=========================================" | Add-Content $out
if ($script:flag) { "VERDICT : INDICATEURS FORTS TROUVES - machine/depots probablement infectes. Voir docs\playbook.md" | Tee-Object -FilePath $out -Append; Write-Host "`nINFECTE - voir $out" -ForegroundColor Red }
elseif ($script:warn) { "VERDICT : indicateurs faibles uniquement - lire chaque fichier signale avant de conclure." | Tee-Object -FilePath $out -Append; Write-Host "`nA VERIFIER - voir $out" -ForegroundColor Yellow }
else { "VERDICT : aucun indicateur PolinRider trouve." | Tee-Object -FilePath $out -Append; Write-Host "`nAucun indicateur trouve. Voir $out" -ForegroundColor Green }
Write-Host "Rapport : $out"
