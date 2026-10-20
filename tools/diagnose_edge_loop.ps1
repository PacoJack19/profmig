<#
.SYNOPSIS
  Reune en un archivo de texto todo lo necesario para entender por que Edge / WebView2 hacen parpadear los iconos de
  un usuario (bucle de avisos de asociaciones de archivos). Solo lee, no modifica nada (salvo con -Aislar, ver abajo).

.DESCRIPTION
  Ejecutar DENTRO de la sesion del usuario afectado, en una PowerShell NORMAL (sin administrador), mientras los
  iconos parpadean. Comprobar antes con 'whoami'.

  Con -Aislar el script cierra Edge/WebView2 unos segundos y mide si el contador deja de subir. Es lo unico que
  cambia el estado (cierra procesos del usuario).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File diagnose_edge_loop.ps1
  powershell -ExecutionPolicy Bypass -File diagnose_edge_loop.ps1 -Aislar
#>
param(
    [string]$Out = (Join-Path $env:TEMP ('diag_edge_{0}.txt' -f $env:USERNAME)),
    [switch]$Aislar
)

$ErrorActionPreference = 'SilentlyContinue'
$sb = New-Object System.Text.StringBuilder
$kExp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'

function Section([string]$title, [scriptblock]$body) {
    [void]$sb.AppendLine("`n===== $title =====")
    try {
        $txt = (& $body | Out-String -Width 230).TrimEnd()
        if ($txt) { [void]$sb.AppendLine($txt) } else { [void]$sb.AppendLine('(sin datos)') }
    } catch { [void]$sb.AppendLine('ERROR: ' + $_.Exception.Message) }
}

function Get-Counter-Rate([int]$seconds) {
    $a = (Get-ItemProperty -Path $kExp).GlobalAssocChangedCounter
    Start-Sleep $seconds
    $b = (Get-ItemProperty -Path $kExp).GlobalAssocChangedCounter
    [pscustomobject]@{ Inicio = $a; Fin = $b; Sube = ($b - $a); PorSegundo = [math]::Round(($b - $a) / $seconds, 1) }
}

Section 'Usuario y equipo' {
    "Usuario : $(whoami)"
    "SID     : $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
    "Equipo  : $env:COMPUTERNAME     Perfil: $env:USERPROFILE"
    "Fecha   : $(Get-Date -Format s)"
    $os = Get-CimInstance Win32_OperatingSystem
    "Windows : $($os.Caption) build $($os.BuildNumber)"
}

Section 'Contador de cambios de asociaciones: ritmo en 20 s (si no sube, el bucle esta parado)' {
    Get-Counter-Rate 20 | Format-List
}

Section 'Procesos Edge / WebView2: quien los lanza (el proceso padre es la aplicacion que los usa)' {
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(msedge|msedgewebview2)\.exe$' }
    $all = @{}; Get-CimInstance Win32_Process | ForEach-Object { $all[[int]$_.ProcessId] = $_ }
    $procs | ForEach-Object {
        $parent = $all[[int]$_.ParentProcessId]
        $cmd = if ($_.CommandLine) { $_.CommandLine } else { '' }
        $type = if ($cmd -match '--type=(\S+)') { $Matches[1] } else { 'principal' }
        [pscustomobject]@{
            Proceso = $_.Name; PID = $_.ProcessId; Sesion = $_.SessionId; Tipo = $type
            Padre = if ($parent) { "$($parent.Name) ($($_.ParentProcessId))" } else { "(ya no existe) $($_.ParentProcessId)" }
            Linea = $cmd.Substring(0, [Math]::Min(150, $cmd.Length))
        }
    } | Where-Object { $_.Tipo -eq 'principal' -or $_.Proceso -eq 'msedgewebview2.exe' } | Sort-Object Proceso, PID | Format-List
}

Section 'Aplicaciones que usan WebView2 en esta sesion (procesos de usuario)' {
    Get-Process | Where-Object { $_.Name -match 'Teams|Outlook|OneDrive|Widgets|PhoneExperience|YourPhone|Copilot|Search|Start|Shell|Office|WINWORD|EXCEL|msteams|Notepad|Clipchamp' } |
        Sort-Object Name | Select-Object Name, Id, StartTime | Format-Table -AutoSize
}

Section 'Claves UserChoice del usuario (deben ser pocas y con su propio SID; si faltan o hay muchas con el SID viejo, hay problema)' {
    $found = New-Object System.Collections.Generic.List[string]
    function Find-UC($key, $path, $depth) {
        if ($depth -gt 7) { return }
        foreach ($n in $key.GetSubKeyNames()) {
            $sub = $null; try { $sub = $key.OpenSubKey($n) } catch { }
            if (-not $sub) { continue }
            if ($n -match '^UserChoice(Latest)?$') { $found.Add("$path\$n") }
            else { Find-UC $sub "$path\$n" ($depth + 1) }
            $sub.Close()
        }
    }
    foreach ($p in 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts', 'Software\Microsoft\Windows\Shell\Associations') {
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($p)
        if ($k) { Find-UC $k $p 0; $k.Close() }
    }
    "Claves UserChoice encontradas: $($found.Count)"
    $found | Select-Object -First 25
    ''
    'ProgId actual de http / https / .pdf:'
    foreach ($p in @('Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice',
                     'Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice',
                     'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice')) {
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($p)
        if ($k) { "  $p => ProgId=$($k.GetValue('ProgId'))"; $k.Close() } else { "  $p => (no existe o sin acceso)" }
    }
}

Section 'Permisos de las claves UserChoice de http / https / .pdf (propietario y ACE; el usuario debe aparecer con su SID actual)' {
    foreach ($p in @('Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice',
                     'Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice',
                     'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice')) {
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($p, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
                 [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        "== $p"
        if ($k) { $k.GetAccessControl().GetSecurityDescriptorSddlForm('Owner,Access'); $k.Close() } else { '   (no se pudo abrir)' }
    }
}

Section 'UCPD (proteccion de aplicaciones predeterminadas)' {
    Get-Service UCPD | Select-Object Name, Status, StartType
    Get-ScheduledTask -TaskName 'UCPD velocity' | Select-Object TaskName, State
}

Section 'Politicas de Edge / WebView2 aplicadas por el dominio (HKLM y HKCU)' {
    foreach ($p in 'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
                   'HKLM:\SOFTWARE\Policies\Microsoft\EdgeWebView2', 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate') {
        "-- $p"
        if (Test-Path $p) { (Get-ItemProperty $p).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "   $($_.Name) = $($_.Value)" } }
        else { '   (no existe)' }
    }
}

Section 'Versiones de Edge y de WebView2' {
    $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if (Test-Path $edge) { "Edge: $((Get-Item $edge).VersionInfo.ProductVersion)" }
    $wv = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    "WebView2 runtime: $($wv.pv)"
}

Section 'Funciones de aislamiento (Sandbox, Application Guard, contenedores). Requiere administrador' {
    Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -match 'Sandbox|ApplicationGuard|Containers|HypervisorPlatform|VirtualMachinePlatform' } |
        Select-Object FeatureName, State
}

Section 'Errores de Edge / WebView2 / shell (ultimas 24 h)' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-24) } |
        Where-Object { $_.Message -match 'msedge|webview|explorer' -and $_.ProviderName -match 'Error|Hang|Reporting' } |
        Select-Object -First 8 TimeCreated, Id, ProviderName, @{ n = 'Mensaje'; e = { ($_.Message -split "`n")[0..2] -join ' | ' } } | Format-List
}

if ($Aislar) {
    Section 'AISLAR: cerrar Edge y WebView2 y medir de nuevo (ritmo del contador en 15 s)' {
        'Antes de cerrar:'
        Get-Counter-Rate 10 | Format-List
        Get-Process msedge, msedgewebview2 | Stop-Process -Force
        Start-Sleep 3
        'Con Edge y WebView2 cerrados:'
        Get-Counter-Rate 15 | Format-List
        'Procesos Edge/WebView2 que han vuelto a aparecer solos:'
        Get-Process msedge, msedgewebview2 | Select-Object Name, Id, StartTime
    }
}

[System.IO.File]::WriteAllText($Out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
$sb.ToString()
Write-Host "`nInforme guardado en $Out"
