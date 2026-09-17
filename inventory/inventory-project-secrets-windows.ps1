# Inventaire des projets : depots git + noms de variables des .env, sur tous les disques.
# Aucune valeur de secret n'est lue. Resultat : Desktop\inventaire-projets.txt
$out = "$env:USERPROFILE\Desktop\inventaire-projets.txt"
"### PROJETS $(Get-Date)" | Set-Content $out -Encoding UTF8
$skip = 'node_modules|\\AppData\\|\\Windows\\|\\Program Files|\\ProgramData\\|\\\$Recycle|\\\.cache\\|\\vendor\\'
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | ForEach-Object { $_.Root }

"`n=== Depots git (chemin -> remote) ===" | Add-Content $out -Encoding UTF8
foreach ($d in $drives) {
  Get-ChildItem $d -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip } | ForEach-Object {
      $p = $_.Parent.FullName
      $r = (git -C $p config --get remote.origin.url 2>$null)
      "$p -> $r" | Add-Content $out -Encoding UTF8
    }
}

"`n=== Fichiers .env : noms de variables uniquement ===" | Add-Content $out -Encoding UTF8
foreach ($d in $drives) {
  Get-ChildItem $d -Recurse -Force -Include ".env", ".env.*" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip -and $_.Name -notmatch 'example|sample|template' } | ForEach-Object {
      "--- $($_.FullName)  ($($_.LastWriteTime.ToString('yyyy-MM-dd')))" | Add-Content $out -Encoding UTF8
      Get-Content $_.FullName -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^\s*[A-Za-z_][A-Za-z0-9_]*\s*=' -and $_ -notmatch '^\s*#' } |
        ForEach-Object { "    " + ($_ -split '=',2)[0].Trim() } | Sort-Object -Unique | Add-Content $out -Encoding UTF8
    }
}

"`n=== Autres fichiers de secrets dans les projets (presence) ===" | Add-Content $out -Encoding UTF8
foreach ($d in $drives) {
  Get-ChildItem $d -Recurse -Force -Include "*.pem","*.key","*.p12","*.jks","*.keystore","serviceAccount*.json","firebase*.json","credentials.json","secrets.json","*.ppk" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip } | ForEach-Object { $_.FullName | Add-Content $out -Encoding UTF8 }
}

"`n### FIN" | Add-Content $out -Encoding UTF8
Write-Host "Ecrit dans $out" -ForegroundColor Green
