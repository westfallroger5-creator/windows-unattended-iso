##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1 does the full setup, auto-detects Dell, triggers Windows Updates using native 25H2 methods,
#   shows Windows Update UI for live progress, enables QMR, logs secure boot.
# - Memory Diagnostic is now ONLY Option 3.
# - NO forced reboot.
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
Write-Host "v2.6 (Live Update UI + QMR + NO auto Memory Test + No Forced Reboot)"

$script:RebootRequired = $false

function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $Message
}

function Remove-DesktopShortcut {
    param ([string]$ShortcutName)
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
        } catch { Write-Log "Syncro install failed: $_" }
    } else { Write-Log "Syncro Agent already installed." }
}

function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed."
        } catch { Write-Log "Chocolatey install error: $_" }
    } else { Write-Log "Chocolatey already installed." }
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
        Start-Process choco -ArgumentList "install dellcommandupdate -y" -Wait
        Write-Log "Dell Command | Update installed."
    } catch { Write-Log "Dell Command install error: $_" }
}

function Install-SoftwarePackages {
    Write-Log "Installing Chrome + Adobe..."
    try {
        Ensure-Chocolatey
        Start-Process choco -ArgumentList "install googlechrome adobereader -y" -Wait
        Write-Log "Software installed."
    } catch { Write-Log "Software install error: $_" }
}

function Set-Hostname {
    Write-Log "Configuring hostname..."
    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    $new = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $new) {
        try {
            Rename-Computer -NewName $new -Force
            Write-Log "Hostname changed to $new (requires reboot)."
            $script:RebootRequired = $true
        } catch {
            Write-Log "Hostname change failed: $_"
        }
    } else {
        Write-Log "Hostname already correct."
    }
}

###############################################################################################################
# ⭐ Windows Updates + UI
###############################################################################################################
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Starting Windows Updates..."

    try {
        Start-Process UsoClient.exe -ArgumentList "StartScan" -WindowStyle Hidden
        Start-Process UsoClient.exe -ArgumentList "StartInstall" -WindowStyle Hidden
        Write-Log "Updates triggered."

        Start-Process "ms-settings:windowsupdate"
        Write-Log "Windows Update UI opened."

        $script:RebootRequired = $true
    }
    catch { Write-Log "Update error: $_" }
}

###############################################################################################################
# ⭐ QMR Registry
###############################################################################################################
function Enable-QuickMachineRecovery {
    Write-Log "Applying Quick Machine Recovery registry keys..."

    $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"
    if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }

    Set-ItemProperty -Path $reg -Name "QuickRecoveryEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "ContinueSearchingEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "LookForSolutionEvery" -Value 0 -Type DWord
    Set-ItemProperty -Path $reg -Name "RestartEvery" -Value 0 -Type DWord

    Write-Log "QMR registry keys applied."
    $script:RebootRequired = $true
}

###############################################################################################################
# ⭐ BitLocker (Option 2)
###############################################################################################################
function Enable-BitLockerDrive {
    param(
        [string]$DriveLetter = "C:",
        [string]$RecoveryKeyPath = "C:\BitLockerRecoveryKey.txt"
    )

    Write-Log "Enabling BitLocker on $DriveLetter..."

    try {
        $bit = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction Stop
        if ($bit.ProtectionStatus -eq "On") {
            Write-Log "BitLocker already enabled."
            return
        }

        Enable-BitLocker -MountPoint $DriveLetter -EncryptionMethod XtsAes256 `
            -UsedSpaceOnly -RecoveryKeyPath $RecoveryKeyPath -TpmProtector

        Write-Log "BitLocker enabled. Recovery key saved to $RecoveryKeyPath."
    }
    catch { Write-Log "BitLocker failed: $_" }
}

###############################################################################################################
# ⭐ UEFI Reboot (Option 4)
###############################################################################################################
function Reboot-ToUEFI {
    Write-Log "Rebooting into UEFI..."
    try {
        shutdown.exe /r /fw /t 0
    } catch { Write-Log "UEFI reboot failed: $_" }
}

###############################################################################################################
# ⭐ SMART FIRST TIME SETUP — MEMORY TEST REMOVED
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

    Write-Log "===== Setup Complete ====="
    Write-Host ">>> Setup finished. Review Windows Update progress, then reboot when ready."
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
        1 { Run-SmartFirstTimeSetup }
        2 { Enable-BitLockerDrive }
        3 { Run-MemoryDiagnostic }
        4 { Reboot-ToUEFI }
        5 { Remove-DesktopShortcut "Computek Setup Script"; exit }
        default { Write-Log "Invalid selection." }
    }
}

###############################################################################################################
# MAIN LOOP
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
