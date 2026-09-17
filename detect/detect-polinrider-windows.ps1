<#
  detect-polinrider-windows.ps1
  Detecteur PolinRider pour Windows — LECTURE SEULE (ne supprime/modifie rien).
  Usage : clic droit sur PowerShell > Executer en tant qu'administrateur, puis :
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\detect-polinrider-windows.ps1
  Resultat : un rapport sur le Bureau (detect-polinrider.txt) + verdict a l'ecran.
  Ce script est auditable : lisez-le avant de l'executer.
#>
$out = "$env:USERPROFILE\Desktop\detect-polinrider.txt"
"### DETECTION POLINRIDER — $(Get-Date) — $env:COMPUTERNAME\$env:USERNAME" | Set-Content $out -Encoding UTF8
$skip = 'node_modules|\\AppData\\Local\\(Temp|Microsoft)|\\Windows\\|\\Program Files|\\\$Recycle'
$roots = @("$env:USERPROFILE") + (Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -gt 0} | ForEach-Object {$_.Root})
$roots = $roots | Select-Object -Unique
$flag = $false
function Hit($msg){ $script:flag=$true; "  [!] $msg" | Tee-Object -FilePath $out -Append }

"`n== 1. Artefact temp_auto_push.bat (fiabilite 100%) ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Filter 'temp_auto_push.bat' -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object { Hit "temp_auto_push.bat : $($_.FullName)" }

"`n== 2. branch_structure.json (IoC confirme) ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Filter 'branch_structure.json' -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object { Hit "branch_structure.json : $($_.FullName)" }

"`n== 3. .vscode/tasks.json auto-executant (runOn: folderOpen) ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Filter 'tasks.json' -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -match '\\.vscode\\' -and $_.FullName -notmatch 'node_modules'} | ForEach-Object {
    if (Select-String -Path $_.FullName -Pattern 'folderOpen' -Quiet -ErrorAction SilentlyContinue) { Hit "tasks.json folderOpen : $($_.FullName)" }
  }

"`n== 4. Marqueurs du payload dans le code ==" | Add-Content $out
$markers = @('rmcej%otb%','Cot%3t=shtP','_$_1e42',"global['_V']","global['!']")
Get-ChildItem $roots -Recurse -Include *.js,*.mjs,*.cjs,*.ts -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object {
    $f=$_.FullName
    foreach($m in $markers){ if (Select-String -Path $f -SimpleMatch -Pattern $m -Quiet -ErrorAction SilentlyContinue){ Hit "marqueur '$m' : $f"; break } }
  }

"`n== 5. Faux fichiers .woff2 (JavaScript deguise) ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Filter '*.woff2' -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object {
    try { $b=[System.IO.File]::ReadAllBytes($_.FullName)[0..3]; $sig=[System.Text.Encoding]::ASCII.GetString($b) } catch { $sig='' }
    if ($sig -ne 'wOF2'){ Hit "faux .woff2 (signature '$sig') : $($_.FullName)" }
  }

"`n== 6. Ligne geante dans un fichier de config (injection ~32000 car.) ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Include *.config.js,*.config.mjs,*.config.cjs,*.config.ts,vite.config.*,postcss.config.*,tailwind.config.*,next.config.*,webpack.config.* -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object {
    $long = Get-Content $_.FullName -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 5000} | Select-Object -First 1
    if ($long){ Hit "ligne de $($long.Length) caracteres : $($_.FullName)" }
  }

"`n== 7. Paquets npm malveillants connus ==" | Add-Content $out
$pkgs='tailwindcss-style-animate|tailwind-mainanimation|tailwind-autoanimation|tailwindcss-typography-style|tailwindcss-style-modify'
Get-ChildItem $roots -Recurse -Include package.json,package-lock.json -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch 'node_modules'} | ForEach-Object {
    if (Select-String -Path $_.FullName -Pattern $pkgs -Quiet -ErrorAction SilentlyContinue){ Hit "paquet malveillant : $($_.FullName)" }
  }

"`n== 8. Traces d'infrastructure C2 ==" | Add-Content $out
Get-ChildItem $roots -Recurse -Include *.js,*.mjs,*.json -File -ErrorAction SilentlyContinue |
  Where-Object {$_.FullName -notmatch $skip} | ForEach-Object {
    if (Select-String -Path $_.FullName -Pattern 'trongrid\.io|aptoslabs\.com|bsc-dataseed|vscode-bootstrapper|default-configuration\.vercel' -Quiet -ErrorAction SilentlyContinue){ Hit "trace C2 : $($_.FullName)" }
  }

"`n== 9. Processus node suspects en cours (node -e / --eval) ==" | Add-Content $out
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
  Where-Object {$_.CommandLine -match '-e |--eval'} | ForEach-Object { Hit "process PID $($_.ProcessId) : $($_.CommandLine)" }

"`n== 10. Persistance (cles Run + taches planifiees recentes) ==" | Add-Content $out
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue |
  ForEach-Object { $_.PSObject.Properties | Where-Object {$_.Value -match 'node|\.js|powershell -enc|curl|wget'} | ForEach-Object { Hit "Run: $($_.Name) = $($_.Value)" } }

"`n=========================================" | Add-Content $out
if ($flag){ "VERDICT : INDICATEURS TROUVES — machine probablement infectee. Voir $out" | Tee-Object -FilePath $out -Append; Write-Host "`nINFECTE — voir $out" -ForegroundColor Red }
else { "VERDICT : aucun indicateur PolinRider trouve." | Tee-Object -FilePath $out -Append; Write-Host "`nAucun indicateur trouve. Voir $out" -ForegroundColor Green }
Write-Host "Rapport : $out"
