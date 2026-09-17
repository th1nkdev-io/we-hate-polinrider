# Triage des projets git : lesquels ont du travail NON POUSSE ?
# Lecture seule. Ne modifie rien. Resultat : Desktop\triage-projets.txt
$out = "$env:USERPROFILE\Desktop\triage-projets.txt"
"### TRIAGE PROJETS $(Get-Date)" | Set-Content $out -Encoding UTF8
$skip = 'node_modules|\\AppData\\|\\Windows\\|\\Program Files|\\\$Recycle|\\vendor\\|\\.cache\\'

# Cherche tous les .git sur tous les disques
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | ForEach-Object { $_.Root }
$repos = foreach ($d in $drives) {
  Get-ChildItem $d -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip } | ForEach-Object { $_.Parent.FullName }
}

$aRisque = 0; $propre = 0
foreach ($r in $repos) {
  $remote = (git -C $r config --get remote.origin.url 2>$null)
  # fichiers modifies non commites
  $dirty  = (git -C $r status --porcelain 2>$null | Measure-Object).Count
  # commits locaux non pousses (toutes branches)
  $ahead = 0
  git -C $r for-each-ref --format='%(upstream:track)' refs/heads 2>$null | ForEach-Object {
    if ($_ -match 'ahead (\d+)') { $ahead += [int]$Matches[1] }
  }
  # branches sans remote du tout = potentiellement jamais poussees
  $noUpstream = (git -C $r for-each-ref --format='%(upstream)' refs/heads 2>$null | Where-Object { $_ -eq '' } | Measure-Object).Count
  $stash = (git -C $r stash list 2>$null | Measure-Object).Count

  if ($dirty -gt 0 -or $ahead -gt 0 -or $noUpstream -gt 0 -or $stash -gt 0) {
    $aRisque++
    "A SAUVER : $r" | Add-Content $out -Encoding UTF8
    "    remote      : $(if($remote){$remote}else{'AUCUN'})" | Add-Content $out -Encoding UTF8
    "    modifies    : $dirty fichier(s) non commite(s)" | Add-Content $out -Encoding UTF8
    "    non pousses : $ahead commit(s) en avance" | Add-Content $out -Encoding UTF8
    "    br sans remote: $noUpstream | stash: $stash" | Add-Content $out -Encoding UTF8
  } else {
    $propre++
  }
}
"" | Add-Content $out -Encoding UTF8
"=== RESUME : $aRisque a sauver, $propre deja a jour (reclonables), $($repos.Count) au total ===" | Add-Content $out -Encoding UTF8
Write-Host "Fini. $aRisque projets a sauver sur $($repos.Count)." -ForegroundColor Green
