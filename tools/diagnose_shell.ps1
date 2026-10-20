<#
.SYNOPSIS
  Reune en un archivo de texto el estado del Explorador / iconos del usuario ACTUAL. Solo lee, no modifica nada.

.DESCRIPTION
  Ejecutar dentro de la sesion del usuario afectado, en una PowerShell NORMAL (no hace falta administrador),
  idealmente mientras los iconos parpadean.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File diagnose_shell.ps1
#>
param([string]$Out = (Join-Path $env:TEMP 'diagnose_shell.txt'))

$ErrorActionPreference = 'SilentlyContinue'
$sb = New-Object System.Text.StringBuilder

function Section([string]$title, [scriptblock]$body) {
    [void]$sb.AppendLine("`n===== $title =====")
    try {
        $txt = (& $body | Out-String -Width 220).TrimEnd()
        if ($txt) { [void]$sb.AppendLine($txt) } else { [void]$sb.AppendLine('(sin datos)') }
    } catch { [void]$sb.AppendLine('ERROR: ' + $_.Exception.Message) }
}

Section 'Usuario y equipo' {
    "Usuario : $(whoami)"
    "SID     : $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
    "Equipo  : $env:COMPUTERNAME"
    "Fecha   : $(Get-Date -Format s)"
    $os = Get-CimInstance Win32_OperatingSystem
    "Windows : $($os.Caption) build $($os.BuildNumber)"
    "Perfil  : $env:USERPROFILE"
}

Section 'Explorer: procesos (si StartTime cambia a cada rato, se reinicia)' {
    Get-Process explorer | Select-Object Id, StartTime, @{n = 'MemMB'; e = { [int]($_.WorkingSet64 / 1MB) } }
}

Section 'Errores y bloqueos de Explorer / shell (ultimas 24 h)' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-24) } |
        Where-Object { $_.ProviderName -in 'Application Error', 'Application Hang', 'Windows Error Reporting' -and
                       $_.Message -match 'explorer|ShellExperience|StartMenu|SearchHost|TextInput' } |
        Select-Object -First 12 TimeCreated, Id, ProviderName, @{ n = 'Mensaje'; e = { ($_.Message -split "`n")[0..3] -join ' | ' } } | Format-List
}

Section 'Shell-Core (operativo)' {
    Get-WinEvent -LogName 'Microsoft-Windows-Shell-Core/Operational' -MaxEvents 15 |
        Select-Object TimeCreated, Id, LevelDisplayName, @{ n = 'Mensaje'; e = { ($_.Message -replace '\s+', ' ') } } | Format-List
}

Section 'Unidades de red y rutas de red heredadas' {
    net use
    ''
    reg query HKCU\Network
}

Section 'Escritorio: ruta, contenido y accesos con destino de red o inexistente' {
    $desk = [Environment]::GetFolderPath('Desktop')
    "Ruta del escritorio: $desk   existe: $(Test-Path $desk)"
    "Elementos: $((Get-ChildItem $desk -Force | Measure-Object).Count)"
    $sh = New-Object -ComObject WScript.Shell
    Get-ChildItem $desk, "$env:PUBLIC\Desktop" -Filter *.lnk -Force | ForEach-Object {
        $t = $sh.CreateShortcut($_.FullName).TargetPath
        [pscustomobject]@{ Nombre = $_.Name; Destino = $t; Existe = $(if ($t -like '\\*') { 'RED' } elseif ($t) { Test-Path $t } else { '(vacio)' }) }
    } | Format-Table -AutoSize
}

Section 'OneDrive' {
    "Variable OneDrive: $env:OneDrive"
    Get-Process OneDrive | Select-Object Id, StartTime
    reg query 'HKCU\Software\Microsoft\OneDrive\Accounts'
}

Section 'Procesos: powershell en ejecucion y mayores consumidores de CPU' {
    Get-Process powershell | Select-Object Id, StartTime
    ''
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name, Id, @{ n = 'CPU_s'; e = { [int]$_.CPU } }, @{ n = 'MemMB'; e = { [int]($_.WorkingSet64 / 1MB) } }
}

Section 'Cachés de iconos y miniaturas (si cambian de hora sin parar, se estan regenerando)' {
    $ex = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
    Get-Item (Join-Path $env:LOCALAPPDATA 'IconCache.db') -Force | Select-Object Name, Length, LastWriteTime
    Get-ChildItem $ex -Force | Where-Object Name -match 'icon|thumb' | Sort-Object Name | Select-Object Name, Length, LastWriteTime
    ''
    "Permisos de la carpeta Explorer:"
    icacls $ex
}

Section 'Registro: iconos y ajustes del Explorador' {
    'WindowMetrics (tamano y profundidad de iconos):'
    Get-ItemProperty 'HKCU:\Control Panel\Desktop\WindowMetrics' | Select-Object 'Shell Icon Size', 'Shell Icon BPP'
    'Explorer\Advanced (seleccion):'
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' |
        Select-Object IconsOnly, ShowTypeOverlay, ShowSyncProviderNotifications, Hidden, HideFileExt, TaskbarAnimations, ListviewAlphaSelect, ListviewShadow
    'Claves de directivas que aun existen en HKCU:'
    reg query 'HKCU\Software\Policies'
    reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies'
}

Section 'Servicios relacionados' {
    Get-Service WSearch, Themes, ShellHWDetection | Select-Object Name, Status, StartType
    ''
    'Defender (tiempo real):'
    (Get-MpComputerStatus).RealTimeProtectionEnabled
}

Section 'Controladores de iconos superpuestos (Windows solo admite 15; los extra provocan iconos que fallan)' {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers' | Select-Object -ExpandProperty PSChildName
}

[System.IO.File]::WriteAllText($Out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
$sb.ToString()
Write-Host "`nInforme guardado en $Out"
