<#
.SYNOPSIS
  Busca referencias al SID VIEJO (como texto o como SID binario) dentro de NTUSER.DAT y UsrClass.dat de un perfil
  migrado: en nombres de claves y en valores. Solo lee, no modifica nada.

.DESCRIPTION
  Ejecutar como Administrador, con el usuario del perfil SIN sesion iniciada (sus hives no pueden estar cargados).
  El SID viejo aparece en el log de la migracion (C:\ProfMig\profmig.log, linea "Perfil origen: ...").

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan_sid_refs.ps1 -Folder C:\Users\prueba1 -OldSid S-1-5-21-111-222-333-1001
#>
param(
    [Parameter(Mandatory)][string]$Folder,
    [Parameter(Mandatory)][string]$OldSid,
    [int]$MaxShow = 60,
    [string]$Out = 'C:\ProfMig\scan_sid_refs.txt',
    [switch]$TestHkcu   # solo para pruebas del script: escanea HKCU en vivo en lugar de montar los hives
)

$ErrorActionPreference = 'Continue'
$sidObj = New-Object System.Security.Principal.SecurityIdentifier($OldSid)
$sidBytes = New-Object byte[] $sidObj.BinaryLength
$sidObj.GetBinaryForm($sidBytes, 0)
$sidHex = [BitConverter]::ToString($sidBytes)

function Scan-Key($key, [string]$path, $hits, $stat) {
    $stat.Keys++
    if ($path.IndexOf($OldSid, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $stat.KeyNames++
        $hits.Add([pscustomobject]@{ Where = 'NOMBRE DE CLAVE'; Key = $path; Value = ''; Kind = '' })
    }
    foreach ($vn in $key.GetValueNames()) {
        try {
            $kind = $key.GetValueKind($vn)
            $v = $key.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        } catch { continue }
        $found = $false
        switch ($kind) {
            'String'       { $found = ($v -is [string]) -and ($v.IndexOf($OldSid, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
            'ExpandString' { $found = ($v -is [string]) -and ($v.IndexOf($OldSid, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
            'MultiString'  { $found = (($v -join "`n").IndexOf($OldSid, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
            'Binary'       { if ($v -is [byte[]] -and $v.Length -ge $sidBytes.Length -and $v.Length -le 262144) {
                                 $found = [BitConverter]::ToString($v).Contains($sidHex) } }
        }
        if ($found) {
            $stat.Values++
            $hits.Add([pscustomobject]@{ Where = 'VALOR'; Key = $path; Value = $vn; Kind = $kind })
        }
    }
    foreach ($sn in $key.GetSubKeyNames()) {
        $sub = $null
        try { $sub = $key.OpenSubKey($sn) } catch { }
        if ($sub) {
            try { Scan-Key $sub "$path\$sn" $hits $stat } finally { $sub.Close() }
        }
    }
}

function Scan-Hive([string]$label, $rootKey) {
    $hits = New-Object System.Collections.Generic.List[object]
    $stat = @{ Keys = 0; KeyNames = 0; Values = 0 }
    Scan-Key $rootKey '' $hits $stat
    [pscustomobject]@{ Label = $label; Stat = $stat; Hits = $hits }
}

function Mount-Hive([string]$name, [string]$file) {
    & reg.exe unload "HKLM\$name" 2>$null | Out-Null
    & reg.exe load "HKLM\$name" $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo cargar $file (esta el usuario con sesion iniciada?)" }
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

$results = @()
if ($TestHkcu) {
    $results += Scan-Hive 'HKCU (prueba)' ([Microsoft.Win32.Registry]::CurrentUser)
} else {
    foreach ($h in @(
        @{ Label = 'NTUSER.DAT';  File = (Join-Path $Folder 'NTUSER.DAT');                                         Name = 'PMSCAN_A' },
        @{ Label = 'UsrClass.dat'; File = (Join-Path $Folder 'AppData\Local\Microsoft\Windows\UsrClass.dat');      Name = 'PMSCAN_B' })) {
        if (-not (Test-Path -LiteralPath $h.File)) { Write-Warning "No existe $($h.File)"; continue }
        Write-Host "Escaneando $($h.Label)..."
        try {
            Mount-Hive $h.Name $h.File
            $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($h.Name)
            try { $results += Scan-Hive $h.Label $root } finally { $root.Close() }
        } finally { Dismount-Hive $h.Name }
    }
}

New-Item -ItemType Directory -Path (Split-Path $Out) -Force | Out-Null
$sw = New-Object System.IO.StreamWriter($Out, $false, (New-Object System.Text.UTF8Encoding($true)))
try {
    $sw.WriteLine("Referencias al SID $OldSid - $(Get-Date -Format s)")
    $sw.WriteLine("Perfil: $Folder")
    foreach ($r in $results) {
        $sw.WriteLine("`n===== $($r.Label) =====")
        $sw.WriteLine("Claves revisadas: $($r.Stat.Keys)   nombres de clave con el SID: $($r.Stat.KeyNames)   valores con el SID: $($r.Stat.Values)")
        # resumen por zona (los 5 primeros componentes de la ruta)
        $r.Hits | Group-Object { ($_.Key.TrimStart('\') -split '\\' | Select-Object -First 5) -join '\' } |
            Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object { $sw.WriteLine(("{0,6}  {1}" -f $_.Count, $_.Name)) }
        $sw.WriteLine("`n-- primeros $MaxShow hallazgos --")
        $r.Hits | Select-Object -First $MaxShow | ForEach-Object { $sw.WriteLine("[$($_.Where)] $($_.Key)  $(if($_.Value){'::'+$_.Value+' ('+$_.Kind+')'})") }
    }
} finally { $sw.Close() }
Get-Content -LiteralPath $Out
Write-Host "`nInforme guardado en $Out"
