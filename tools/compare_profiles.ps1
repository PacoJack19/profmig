<#
.SYNOPSIS
  Compara los permisos (carpetas) y las ACL del registro (NTUSER.DAT) de dos perfiles de la MISMA cuenta:
  uno migrado con profmig y uno limpio creado por Windows. Sirve para encontrar que hace distinto al migrado.

.DESCRIPTION
  Ejecutar como Administrador, desde OTRA cuenta (ninguno de los dos perfiles puede estar cargado).
  No modifica nada: solo lee. Escribe el informe en -Out y lo muestra por pantalla.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File compare_profiles.ps1 -Migrated C:\Users\usuario -Fresh C:\Users\usuario.DOMINIO
#>
param(
    [Parameter(Mandatory)][string]$Migrated,
    [Parameter(Mandatory)][string]$Fresh,
    [int]$FolderDepth = 4,
    [string]$Out = 'C:\ProfMig\compare_profiles.txt',
    [switch]$SkipRegistry
)

$ErrorActionPreference = 'Continue'
$sidCache = @{}

# SID -> nombre legible (si no se resuelve se deja el SID: suele ser un resto del dominio anterior)
function Resolve-Sddl([string]$sddl) {
    [regex]::Replace($sddl, 'S-1-[0-9\-]+', {
        param($m)
        $s = $m.Value
        if (-not $sidCache.ContainsKey($s)) {
            try { $sidCache[$s] = (New-Object System.Security.Principal.SecurityIdentifier($s)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $sidCache[$s] = "$s(NO-RESUELVE)" }
        }
        $sidCache[$s]
    })
}

function Get-SddlOf([string]$path) {
    try { Resolve-Sddl ((Get-Acl -LiteralPath $path -ErrorAction Stop).GetSecurityDescriptorSddlForm('Owner,Access')) }
    catch { 'ERROR: ' + $_.Exception.Message }
}

# ------------------------------------------------------------------ carpetas
function Walk-Dirs($dir, [int]$depth, $list) {
    $list.Add($dir)
    if ($depth -le 0) { return }
    foreach ($d in Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -ErrorAction SilentlyContinue) {
        if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }   # junctions: no se siguen
        Walk-Dirs $d ($depth - 1) $list
    }
}

function Get-FolderFingerprint([string]$root, [int]$depth) {
    $map = @{}
    $root = $root.TrimEnd('\')
    $items = New-Object System.Collections.Generic.List[object]
    Walk-Dirs (Get-Item -LiteralPath $root -Force) $depth $items
    foreach ($f in 'NTUSER.DAT', 'AppData\Local\Microsoft\Windows\UsrClass.dat') {
        $p = Join-Path $root $f
        if (Test-Path -LiteralPath $p) { $items.Add((Get-Item -LiteralPath $p -Force)) }
    }
    foreach ($i in $items) {
        $rel = $i.FullName.Substring($root.Length).TrimStart('\')
        if (-not $rel) { $rel = '.' }
        $map['FS:' + $rel] = Get-SddlOf $i.FullName
    }
    $map
}

# ------------------------------------------------------------------ registro
# Se usa .NET directamente: Get-Acl -LiteralPath falla con algunas claves del registro en PowerShell 5.1.
# Las claves se leen bajo HKLM\<prefijo> (el hive montado). $script:RegRoot se puede cambiar para pruebas.
$script:RegRoot = [Microsoft.Win32.Registry]::LocalMachine

function Join-KeyPath([string]$prefix, [string]$rel) { (@($prefix, $rel) | Where-Object { $_ }) -join '\' }

function Get-KeySddl([string]$path) {
    try {
        $k = $script:RegRoot.OpenSubKey($path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
                                        [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if (-not $k) { return $null }
        try { Resolve-Sddl ($k.GetAccessControl().GetSecurityDescriptorSddlForm('Owner,Access')) } finally { $k.Close() }
    } catch { 'ERROR: ' + $_.Exception.Message }
}

function Get-SubKeyNames([string]$path) {
    try {
        $k = $script:RegRoot.OpenSubKey($path)
        if ($k) { try { $k.GetSubKeyNames() } finally { $k.Close() } }
    } catch { }
}

function Walk-Keys([string]$prefix, [string]$rel, [int]$depth, $map) {
    $path = Join-KeyPath $prefix $rel
    $sddl = Get-KeySddl $path
    if ($null -eq $sddl) { return }   # la clave no existe en este perfil
    $map['REG:' + $(if ($rel) { $rel } else { '<raiz>' })] = $sddl
    if ($depth -le 0) { return }
    foreach ($name in Get-SubKeyNames $path) { Walk-Keys $prefix (Join-KeyPath $rel $name) ($depth - 1) $map }
}

function Get-HiveFingerprint([string]$prefix) {
    $map = @{}
    Walk-Keys $prefix '' 1 $map
    foreach ($p in @(
        @('Environment', 1), @('Volatile Environment', 1), @('Control Panel', 2), @('Software\Policies', 3),
        @('Software\Microsoft\Windows\CurrentVersion', 2), @('Software\Microsoft\Windows NT\CurrentVersion', 2),
        @('Software\Microsoft\Windows\CurrentVersion\Explorer', 2))) {
        Walk-Keys $prefix $p[0] $p[1] $map
    }
    $map
}

function Mount-Hive([string]$name, [string]$file) {
    & reg.exe unload "HKLM\$name" 2>$null | Out-Null
    & reg.exe load "HKLM\$name" $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo cargar $file (esta en uso?)" }
}
function Dismount-Hive([string]$name) {
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    for ($i = 0; $i -lt 6; $i++) {
        & reg.exe unload "HKLM\$name" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep 1
    }
    Write-Warning "No se pudo descargar HKLM\$name"
}

# ------------------------------------------------------------------ comparacion
function Compare-Maps($a, $b, [string]$title, $sw) {
    $sw.WriteLine("`n===== $title =====")
    $common = $a.Keys | Where-Object { $b.ContainsKey($_) } | Sort-Object
    $diff = $common | Where-Object { $a[$_] -ne $b[$_] }
    $onlyA = @($a.Keys | Where-Object { -not $b.ContainsKey($_) } | Sort-Object)
    $onlyB = @($b.Keys | Where-Object { -not $a.ContainsKey($_) } | Sort-Object)
    $sw.WriteLine("Elementos comparados: $(@($common).Count)   con ACL distinta: $(@($diff).Count)   solo en migrado: $($onlyA.Count)   solo en limpio: $($onlyB.Count)")
    foreach ($k in $diff) {
        $sw.WriteLine("`n[DIFERENTE] $k")
        $sw.WriteLine("   migrado: $($a[$k])")
        $sw.WriteLine("   limpio : $($b[$k])")
    }
    if ($onlyA.Count) { $sw.WriteLine("`n[SOLO EN MIGRADO] (primeros 60)"); $onlyA | Select-Object -First 60 | ForEach-Object { $sw.WriteLine("   $_") } }
    if ($onlyB.Count) { $sw.WriteLine("`n[SOLO EN LIMPIO] (primeros 60)"); $onlyB | Select-Object -First 60 | ForEach-Object { $sw.WriteLine("   $_") } }
}

New-Item -ItemType Directory -Path (Split-Path $Out) -Force | Out-Null
$sw = New-Object System.IO.StreamWriter($Out, $false, (New-Object System.Text.UTF8Encoding($true)))
try {
    $sw.WriteLine("Comparacion de perfiles - $(Get-Date -Format s)")
    $sw.WriteLine("Migrado: $Migrated")
    $sw.WriteLine("Limpio : $Fresh")

    Write-Host 'Leyendo permisos de carpetas (puede tardar un par de minutos)...'
    $fa = Get-FolderFingerprint $Migrated $FolderDepth
    $fb = Get-FolderFingerprint $Fresh $FolderDepth
    Compare-Maps $fa $fb "CARPETAS (profundidad $FolderDepth)" $sw

    if (-not $SkipRegistry) {
        Write-Host 'Montando hives y leyendo ACL del registro...'
        try {
            Mount-Hive 'PMCMP_A' (Join-Path $Migrated 'NTUSER.DAT')
            $ra = Get-HiveFingerprint 'PMCMP_A'
        } finally { Dismount-Hive 'PMCMP_A' }
        try {
            Mount-Hive 'PMCMP_B' (Join-Path $Fresh 'NTUSER.DAT')
            $rb = Get-HiveFingerprint 'PMCMP_B'
        } finally { Dismount-Hive 'PMCMP_B' }
        Compare-Maps $ra $rb 'REGISTRO (NTUSER.DAT)' $sw
    }
} finally {
    $sw.Close()
}
Get-Content -LiteralPath $Out
Write-Host "`nInforme guardado en $Out"
