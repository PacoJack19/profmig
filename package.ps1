<#
.SYNOPSIS
  Compila profmig en modo Release desde cero y genera el paquete distribuible en dist\profmig-<version>.zip.

.DESCRIPTION
  Requiere cmake, ninja y g++ (MSYS2 UCRT64). Por defecto busca en C:\msys64\ucrt64\bin.
  El paquete contiene: profmig.exe, GUIA_RAPIDA.md, README.md, tools\*.ps1 y SHA256SUMS.txt.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File package.ps1
#>
param(
    [string]$MsysBin = 'C:\msys64\ucrt64\bin',
    [switch]$Strip,      # quitar simbolos (exe mas pequeno; algunos antivirus lo toleran peor)
    [switch]$NoBuild     # reutilizar build-dist\profmig.exe (solo rehace el paquete: misma firma binaria, mismo hash)
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (Test-Path $MsysBin) { $env:PATH = "$MsysBin;$env:PATH" }

if (-not $NoBuild) {
    foreach ($tool in 'cmake', 'ninja', 'g++') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "No se encuentra '$tool' en el PATH (ver -MsysBin)." }
    }
}

$cml = Get-Content (Join-Path $root 'CMakeLists.txt') -Raw
if ($cml -notmatch 'project\(profmig VERSION (\d+\.\d+\.\d+)') { throw 'No se pudo leer la version de CMakeLists.txt' }
$ver = $Matches[1]
Write-Host "== profmig $ver ==" -ForegroundColor Cyan

# 1) Compilacion limpia en Release (o reutilizar la ultima con -NoBuild)
$build = Join-Path $root 'build-dist'
$exe = Join-Path $build 'profmig.exe'
if ($NoBuild) {
    if (-not (Test-Path $exe)) { throw 'Con -NoBuild hace falta un build-dist\profmig.exe previo.' }
    Write-Host 'Reutilizando el ejecutable ya compilado (-NoBuild).'
} else {
    if (Test-Path $build) { Remove-Item $build -Recurse -Force }
    $stripFlag = if ($Strip) { 'ON' } else { 'OFF' }
    Write-Host 'Configurando...'
    & cmake -S $root -B $build -G Ninja -DCMAKE_BUILD_TYPE=Release "-DPROFMIG_STRIP=$stripFlag" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fallo la configuracion de CMake.' }
    Write-Host 'Compilando...'
    & cmake --build $build
    if ($LASTEXITCODE -ne 0) { throw 'Fallo la compilacion.' }
}
if (-not (Test-Path $exe)) { throw 'No se genero profmig.exe' }

# 2) Carpeta del paquete
$dist = Join-Path $root 'dist'
$pkg = Join-Path $dist "profmig-$ver"
if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
New-Item -ItemType Directory -Path $pkg, (Join-Path $pkg 'tools') -Force | Out-Null
Copy-Item $exe (Join-Path $pkg 'profmig.exe')
Copy-Item (Join-Path $root 'docs\GUIA_RAPIDA.md') $pkg
Copy-Item (Join-Path $root 'README.md') $pkg
Get-ChildItem (Join-Path $root 'tools') -Filter *.ps1 | Copy-Item -Destination (Join-Path $pkg 'tools')

# 3) Sumas de verificacion (formato sha256sum: HASH *ruta)
$lines = Get-ChildItem $pkg -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($pkg.Length + 1)
    '{0} *{1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
}
[System.IO.File]::WriteAllLines((Join-Path $pkg 'SHA256SUMS.txt'), $lines, (New-Object System.Text.UTF8Encoding($false)))

# 4) ZIP
$zip = Join-Path $dist "profmig-$ver.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $pkg '*') -DestinationPath $zip -CompressionLevel Optimal
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
[System.IO.File]::WriteAllText("$zip.sha256", "$zipHash *profmig-$ver.zip`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "Paquete: $zip" -ForegroundColor Green
Write-Host ("Tamano : {0:N1} MB   SHA256: {1}" -f ((Get-Item $zip).Length / 1MB), $zipHash)
$lines | ForEach-Object { Write-Host "  $_" }
