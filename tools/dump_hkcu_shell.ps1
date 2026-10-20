<#
.SYNOPSIS
  Vuelca a un archivo de texto los ajustes del Explorador / escritorio / iconos del usuario ACTUAL (HKCU) y los
  controladores de shell registrados solo para ese usuario. Sirve para comparar un perfil que falla con uno sano.
  Solo lee, no modifica nada.

.DESCRIPTION
  Ejecutar en la sesion de CADA usuario, en una PowerShell NORMAL (sin administrador: el administrador con otras
  credenciales leeria el HKCU equivocado). Comprobar antes con 'whoami'.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File dump_hkcu_shell.ps1
#>
param([string]$Out = (Join-Path $env:TEMP ("hkcu_shell_{0}.txt" -f $env:USERNAME)))

$ErrorActionPreference = 'SilentlyContinue'
$lines = New-Object System.Collections.Generic.List[string]
$hkcu = [Microsoft.Win32.Registry]::CurrentUser

# Subarboles del Explorador que cambian constantemente (historiales): solo ruido para comparar
$skip = 'RecentDocs|UserAssist|ComDlg32|\\Streams|TypedPaths|RunMRU|WordWheelQuery|FeatureUsage|SearchHistory|' +
        'Taskband|StartPage2|CIDOpen|CIDSave|LastVisitedPidlMRU|OpenSavePidlMRU|BagMRU|\\Bags\\|MenuOrder|Modules|' +
        'ProcessedSearchRoots|Search\\RecentApps|ApplicationAssociationToasts|FileExts'

function Format-Val($v, $kind) {
    switch ($kind) {
        'Binary'      { $b = [byte[]]$v; $h = ([BitConverter]::ToString($b, 0, [Math]::Min(16, $b.Length))); "bin[$($b.Length)] $h" }
        'MultiString' { 'multi: ' + (($v) -join ' | ') }
        default       { [string]$v }
    }
}

function Dump-Key([string]$path, [int]$depth, [bool]$valuesOnly = $false) {
    if ($path -match $skip) { return }
    $k = $hkcu.OpenSubKey($path)
    if (-not $k) { $lines.Add("## (no existe) HKCU\$path"); return }
    try {
        foreach ($vn in ($k.GetValueNames() | Sort-Object)) {
            $kind = $k.GetValueKind($vn)
            $v = $k.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
            $name = if ($vn) { $vn } else { '(predeterminado)' }
            $lines.Add("HKCU\$path :: $name [$kind] = $(Format-Val $v $kind)")
        }
        if ($depth -gt 0) {
            foreach ($sn in ($k.GetSubKeyNames() | Sort-Object)) { Dump-Key "$path\$sn" ($depth - 1) }
        } else {
            $n = $k.SubKeyCount
            if ($n) { $lines.Add("HKCU\$path :: <$n subclaves>") }
        }
    } finally { $k.Close() }
}

$lines.Add("Usuario: $(whoami)   SID: $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)   Fecha: $(Get-Date -Format s)")
$lines.Add("Perfil: $env:USERPROFILE")

# Escala de pantalla, metricas, tema, DWM
foreach ($p in @(
    @('Control Panel\Desktop', 2), @('Control Panel\International', 0), @('Control Panel\Colors', 0),
    @('Software\Microsoft\Windows\DWM', 1),
    @('Software\Microsoft\Windows\CurrentVersion\Themes', 2),
    @('Software\Microsoft\Windows\CurrentVersion\ThemeManager', 1),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer', 0),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 1),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons', 0),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers', 1),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop', 0),
    @('Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons', 2),
    @('Software\Microsoft\Windows\CurrentVersion\ShellExtensions', 3),
    @('Software\Microsoft\Windows\CurrentVersion\Applets', 0),
    @('Software\Microsoft\Windows\Shell', 0),
    @('Software\Microsoft\Windows\ShellNoRoam', 0),
    @('Software\Microsoft\Windows NT\CurrentVersion\Windows', 1),
    @('Environment', 1),
    @('Software\Microsoft\Windows\CurrentVersion\Run', 1),
    @('Software\Microsoft\Windows\CurrentVersion\RunOnce', 1))) {
    Dump-Key $p[0] $p[1]
}

# Controladores de shell registrados SOLO para este usuario (HKCU\Software\Classes = UsrClass.dat)
$lines.Add('')
$lines.Add('### Controladores de shell por usuario (HKCU\Software\Classes)')
foreach ($ci in @('Software\Classes\CLSID')) {
    $c = $hkcu.OpenSubKey($ci)
    if ($c) {
        $names = $c.GetSubKeyNames() | Sort-Object
        $lines.Add("CLSID por usuario: $($names.Count)")
        foreach ($n in $names) {
            $srv = $hkcu.OpenSubKey("$ci\$n\InprocServer32")
            $lines.Add("CLSID $n  InprocServer32 = $(if ($srv) { $srv.GetValue('') })")
            if ($srv) { $srv.Close() }
        }
        $c.Close()
    }
}
# Manejadores de iconos y DefaultIcon propios del usuario
$cls = $hkcu.OpenSubKey('Software\Classes')
if ($cls) {
    $all = $cls.GetSubKeyNames()
    $lines.Add("Claves de primer nivel en HKCU\Software\Classes: $($all.Count)")
    foreach ($n in ($all | Sort-Object)) {
        $ih = $hkcu.OpenSubKey("Software\Classes\$n\ShellEx\IconHandler")
        if ($ih) { $lines.Add("IconHandler  $n = $($ih.GetValue(''))"); $ih.Close() }
        $di = $hkcu.OpenSubKey("Software\Classes\$n\DefaultIcon")
        if ($di) { $lines.Add("DefaultIcon  $n = $($di.GetValue(''))"); $di.Close() }
    }
    $cls.Close()
}

[System.IO.File]::WriteAllLines($Out, $lines, (New-Object System.Text.UTF8Encoding($true)))
"Lineas: $($lines.Count)"
Write-Host "Informe guardado en $Out"
