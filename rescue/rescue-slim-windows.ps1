# Sauvetage des projets a preserver, SANS node_modules ni caches, AVEC le .git.
# Lit Desktop\triage-projets.txt, copie chaque projet "A SAUVER" vers C:\_RESCUE.
# Ne modifie AUCUN projet source (lecture seule cote source).
$ErrorActionPreference = 'Continue'
$triage = "$env:USERPROFILE\Desktop\triage-projets.txt"
$dest   = "C:\_RESCUE"
$manifest = "$dest\_manifest.txt"

if (-not (Test-Path $triage)) { Write-Host "triage-projets.txt introuvable sur le Bureau." -ForegroundColor Red; exit }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
"### SAUVETAGE $(Get-Date)" | Set-Content $manifest -Encoding UTF8

# Dossiers a NE PAS copier (exclus a tous les niveaux -> monorepos OK). Le .git est CONSERVE.
$excl = @('node_modules','.pnpm-store','dist','build','.next','.nuxt','.turbo','.expo',
          'coverage','vendor','.output','.cache','tmp','.vercel','.netlify','android/app/build','ios/Pods')

# Extraire les chemins "A SAUVER : <path>"
$paths = Select-String -Path $triage -Pattern '^A SAUVER : (.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
Write-Host "$($paths.Count) projets a copier..." -ForegroundColor Cyan

$i = 0
foreach ($p in $paths) {
  $i++
  if (-not (Test-Path $p)) { "MANQUANT : $p" | Add-Content $manifest; continue }
  # nom de dossier unique et court derive du chemin
  $safe = ($p -replace '^[A-Za-z]:\\','' -replace '[\\/]','_' -replace '[^A-Za-z0-9._-]','')
  $target = Join-Path $dest $safe
  $remote = (git -C $p config --get remote.origin.url 2>$null)
  "[$i/$($paths.Count)] $safe  <=  $p   ($remote)" | Tee-Object -FilePath $manifest -Append | Out-Null
  Write-Host "[$i/$($paths.Count)] $safe" -ForegroundColor Green
  # robocopy : /E tout l'arbre, /XD exclut les dossiers lourds partout, /R:1 /W:1 rapide, /NFL /NDL /NP silencieux
  $xd = $excl | ForEach-Object { $_ }
  robocopy $p $target /E /XD @xd /R:1 /W:1 /NFL /NDL /NP /NJH /NJS | Out-Null
}

# Taille finale
$size = "{0:N1} Go" -f ((Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1GB)
"" | Add-Content $manifest
"=== $($paths.Count) projets copies. Taille totale : $size ===" | Add-Content $manifest
Write-Host "`nTermine. $($paths.Count) projets dans $dest  ($size)." -ForegroundColor Cyan
Write-Host "Copiez le dossier C:\_RESCUE entier sur votre cle USB." -ForegroundColor Yellow
