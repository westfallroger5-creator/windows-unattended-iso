##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1 does the full setup, auto-detects Dell, triggers Windows Updates using native 25H2 methods,
#   shows Windows Update UI for live progress, enables QMR, logs secure boot, schedules memtest.
# - NO forced reboot. Tech decides when to reboot.
# - Cleanup happens ONLY on Exit (Option 5).
##########################################################################################################################################################

function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

$LogDirectory = "$env:APPDATA\Computek"
$LogFile = "$LogDirectory\SetupLog.txt"
if (-not (Test-Path -Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

$asciiArt = @"
  #####                                    #######               
 #     #  ####  #    # #####  #    #          #    ###### #    # 
 #       #    # ##  ## #    # #    #          #    #      #   #  
 #       #    # # ## # #    # #    # #####    #    #####  ####   
 #       #    # #    # #####  #    #          #    #      #  #   
 #     # #    # #    # #      #    #          #    #      #   #  
  #####   ####  #    # #       ####           #    ###### #    # 
"@
Write-Host $asciiArt -ForegroundColor Black
Write-Host "Welcome to the System Management Script!"
Write-Host "v2.5 (Live Update UI + Native Update Engine + No Auto Reboot + QMR Registry Enable)"

$script:RebootRequired = $false

function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $Message
}

function Remove-DesktopShortcut {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ShortcutName
    )
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcut = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $shortcut) {
        Remove-Item $shortcut -Force
        Write-Log "Removed desktop shortcut: $ShortcutName"
    }
}

function Install-SyncroAgent {
    Write-Log "Installing Syncro Agent..."
    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $path = "C:\Windows\Temp\SyncroSetup.exe"
        $args = "--console --customerid 1362064 --folderid 4238852"

        try {
            Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing
            Start-Process $path -ArgumentList $args -Wait
            Write-Log "Syncro Agent installed."
        } catch {
            Write-Log "Syncro install failed: $_"
        }
    } else {
        Write-Log "Syncro Agent already installed."
    }
}

function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed."
        } catch {
            Write-Log "Chocolatey install error: $_"
        }
    } else {
        Write-Log "Chocolatey already installed."
    }
}

function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        Write-Log "Unable to detect manufacturer."
        return $false
    }
}

function Install-DellCommandUpdate {
    Write-Log "Installing Dell Command | Update..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install dellcommandupdate -y" -NoNewWindow -Wait
        Write-Log "Dell Command | Update installed."
    } catch {
        Write-Log "Dell Command install error: $_"
    }
}

function Install-SoftwarePackages {
    Write-Log "Installing software (Chrome, Adobe Reader)..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install googlechrome adobereader -y" -NoNewWindow -Wait
        Write-Log "Software installed."
    } catch {
        Write-Log "Software install error: $_"
    }
}

function Set-Hostname {
    Write-Log "Configuring hostname..."
    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $new = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $new) {
        try {
            Rename-Computer -NewName $new -Force
            Write-Log "Set hostname to $new (reboot required later)."
            $script:RebootRequired = $true
        } catch {
            Write-Log "Hostname change failed: $_"
        }
    } else {
        Write-Log "Hostname already correct."
    }
}

###############################################################################################################
# ⭐ **Native Windows Updates + Opens Windows Update UI for Live Progress**
###############################################################################################################
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Initializing Windows Update..."

    try {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service bits -Force -ErrorAction SilentlyContinue

        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue

        Start-Service wuauserv -ErrorAction SilentlyContinue
        Start-Service bits -ErrorAction SilentlyContinue

        Write-Log "Triggering update scan..."
        Start-Process "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden

        Write-Log "Triggering install..."
        Start-Process "UsoClient.exe" -ArgumentList "StartInstall" -WindowStyle Hidden

        Write-Log "Opening Windows Update UI for real-time progress..."
        Start-Process "ms-settings:windowsupdate"

        Write-Log "Windows Update running in background with UI visible."

        $script:RebootRequired = $true

    } catch {
        Write-Log "Update engine error: $_"
    }
}

function Run-MemoryDiagnostic {
    Write-Log "Scheduling Memory Diagnostic..."
    try {
        Start-Process "mdsched.exe" -ArgumentList "/restart" -WindowStyle Hidden
        Write-Log "Memory test scheduled for next reboot."
        $script:RebootRequired = $true
    } catch {
        Write-Log "Memory Diagnostic scheduling error: $_"
    }
}

function Check-SecureBootStatus {
    try {
        $val = Confirm-SecureBootUEFI
        if ($val) { Write-Log "Secure Boot ENABLED." }
        else { Write-Log "Secure Boot DISABLED." }
    } catch {
        Write-Log "Secure Boot not supported."
    }
}

###############################################################################################################
# ⭐ **Quick Machine Recovery (Registry)**  
###############################################################################################################
function Enable-QuickMachineRecovery {
    Write-Log "Applying Quick Machine Recovery registry keys..."

    $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"

    if (-not (Test-Path $reg)) {
        New-Item -Path $reg -Force | Out-Null
    }

    Set-ItemProperty -Path $reg -Name "QuickRecoveryEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "ContinueSearchingEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "LookForSolutionEvery" -Value 0 -Type DWord
    Set-ItemProperty -Path $reg -Name "RestartEvery" -Value 0 -Type DWord

    Write-Log "QMR registry settings applied. Toggle requires reboot after updates."

    $script:RebootRequired = $true
}

###############################################################################################################
# ⭐ **SMART FIRST TIME SETUP**
###############################################################################################################
function Run-SmartFirstTimeSetup {
    Write-Log "===== Running Smart Auto Setup ====="

    Install-SyncroAgent

    if (Is-DellSystem) { Install-DellCommandUpdate }
    else { Write-Log "Non-Dell detected: Skipping Dell Command Update." }

    Install-SoftwarePackages
    Set-Hostname
    Enable-QuickMachineRecovery
    Install-WindowsUpdates-GetMeUpToDate
    Check-SecureBootStatus
    Run-MemoryDiagnostic

    Write-Log "===== Setup Complete. Reboot Recommended. ====="
    Write-Host ""
    Write-Host ">>> Setup is complete. Press ENTER after reviewing update progress."
    Pause
}

###############################################################################################################
# MENU
###############################################################################################################
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. Enable BitLocker on C:"
    Write-Host "3. Run Windows Memory Diagnostic (Manual)"
    Write-Host "4. Reboot to UEFI Firmware Settings"
    Write-Host "5. Exit and Cleanup"
    Write-Host "=========================================="
}

function MenuSelection {
    param ([int]$selection)

    switch ($selection) {
        1  { Run-SmartFirstTimeSetup }
        2  { Enable-BitLockerDrive }
        3  { Run-MemoryDiagnostic }
        4  { Reboot-ToUEFI }
        5  { Remove-DesktopShortcut -ShortcutName "Computek Setup Script"; exit }
        default { Write-Log "Invalid selection." }
    }
}

###############################################################################################################
# MAIN
###############################################################################################################
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Log "Administrator required. Exiting."
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Enter choice (1-5) [Default = 1]"
    if ($choice -match '^\d+$') { $choice = [int]$choice } else { $choice = 1 }
    MenuSelection -selection $choice
    Pause
} while ($true)
