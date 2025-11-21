##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1 does the full setup, auto-detects Dell, triggers Windows Updates via native Settings engine,
#   enables QMR, logs secure boot, schedules memtest, and reboots at the end.
# - Option 2 keeps BitLocker manual.
# - Cleanup happens ONLY on Exit (Option 5). Active Hours are never modified.
##########################################################################################################################################################

# Function: Set console text and background colors
function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

# Log file setup
$LogDirectory = "$env:APPDATA\Computek"
$LogFile = "$LogDirectory\SetupLog.txt"
if (-not (Test-Path -Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# ASCII art and welcome message
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
Write-Host "v2.3 (Smart Auto Mode + Native Windows Update Engine + QMR Registry Enable)"

# Global reboot flag
$script:RebootRequired = $false

# Function: Log messages to file and console
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $Message
}

# Function: Remove desktop shortcut (cleanup-only)
function Remove-DesktopShortcut {
    param ([string]$ShortcutName)

    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "$ShortcutName.lnk"

    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Write-Log "Shortcut '$ShortcutName' removed."
    }
}

# Function: Install Syncro Agent
function Install-SyncroAgent {
    Write-Log "Installing Syncro Agent..."

    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $Url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $SavePath = "C:\Windows\Temp\SyncroSetup.exe"
        $Args = "--console --customerid 1362064 --folderid 4238852"

        try {
            Invoke-WebRequest -Uri $Url -OutFile $SavePath -UseBasicParsing
            Start-Process -FilePath $SavePath -ArgumentList $Args -Wait
            Write-Log "Syncro Agent installed."
        } catch {
            Write-Log "Failed to install Syncro Agent: $_"
        }
    }
    else {
        Write-Log "Syncro Agent already installed."
    }
}

# Chocolatey install
function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey not found. Installing..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed."
        } catch {
            Write-Log "Chocolatey install failed: $_"
            throw
        }
    }
    else {
        Write-Log "Chocolatey already installed."
    }
}

# Detect Dell
function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        Write-Log "Failed to read manufacturer: $_"
        return $false
    }
}

# Dell Command Update
function Install-DellCommandUpdate {
    Write-Log "Installing Dell Command | Update..."

    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install dellcommandupdate -y" -Wait -NoNewWindow
        Write-Log "Dell Command | Update installed."
    } catch {
        Write-Log "Failed to install DCU: $_"
    }
}

# Software Packages
function Install-SoftwarePackages {
    Write-Log "Installing software packages..."

    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install googlechrome adobereader -y" -Wait -NoNewWindow
        Write-Log "Packages installed."
    } catch {
        Write-Log "Software install failed: $_"
    }
}

# Hostname
function Set-Hostname {
    Write-Log "Setting hostname..."

    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    $newName = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $newName) {
        try {
            Rename-Computer -NewName $newName -Force
            Write-Log "Hostname set → $newName"
            $script:RebootRequired = $true
        } catch {
            Write-Log "Hostname failed: $_"
        }
    }
    else {
        Write-Log "Hostname already correct."
    }
}

# ⭐ Native Windows Update (Settings-style) ⭐
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Starting Windows Updates using native Settings engine..."

    try {
        Write-Log "Resetting Windows Update components..."
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service bits -Force -ErrorAction SilentlyContinue

        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue

        Start-Service wuauserv -ErrorAction SilentlyContinue
        Start-Service bits -ErrorAction SilentlyContinue

        Write-Log "Triggering Windows Update scan..."
        Start-Process "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden

        Write-Log "Triggering Windows Update download..."
        Start-Process "UsoClient.exe" -ArgumentList "StartDownload" -WindowStyle Hidden

        Write-Log "Triggering Windows Update install..."
        Start-Process "UsoClient.exe" -ArgumentList "StartInstall" -WindowStyle Hidden

        Write-Log "Forcing legacy update handler..."
        Start-Process "wuauclt.exe" -ArgumentList "/updatenow" -WindowStyle Hidden

        Write-Log "Updates running in background. Reboot required when complete."
        $script:RebootRequired = $true
    }
    catch {
        Write-Log "Windows Update trigger failed: $_"
    }
}

# Bitlocker
function Enable-BitLockerDrive {
    param ([string]$DriveLetter = "C:", [string]$RecoveryKeyPath = "C:\BitLockerRecoveryKey.txt")

    try {
        $vol = Get-BitLockerVolume -MountPoint $DriveLetter

        if ($vol.ProtectionStatus -eq "On") {
            Write-Log "BitLocker already enabled."
        }
        else {
            Enable-BitLocker -MountPoint $DriveLetter -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                -RecoveryKeyPath $RecoveryKeyPath -TpmProtector
            Write-Log "BitLocker enabled. Key saved to $RecoveryKeyPath"
        }
    } catch {
        Write-Log "BitLocker failed: $_"
    }
}

# Memtest
function Run-MemoryDiagnostic {
    Write-Log "Scheduling Windows Memory Diagnostic..."
    try {
        Start-Process "mdsched.exe" -ArgumentList "/restart" -WindowStyle Hidden
        Write-Log "Memory Diagnostic scheduled for reboot."
        $script:RebootRequired = $true
    } catch {
        Write-Log "Failed to schedule: $_"
    }
}

# Secure Boot
function Check-SecureBootStatus {
    try {
        if (Confirm-SecureBootUEFI) {
            Write-Log "Secure Boot ENABLED."
        } else {
            Write-Log "Secure Boot DISABLED."
        }
    } catch {
        Write-Log "Secure Boot not supported."
    }
}

# QMR Enable (Registry)
function Enable-QuickMachineRecovery {
    Write-Log "Enabling Quick Machine Recovery..."

    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"
        if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }

        Set-ItemProperty $path QuickRecoveryEnabled 1 -Type DWord
        Set-ItemProperty $path ContinueSearchingEnabled 1 -Type DWord
        Set-ItemProperty $path LookForSolutionEvery 0 -Type DWord
        Set-ItemProperty $path RestartEvery 0 -Type DWord

        Write-Log "QMR enabled (UI toggle will show ON after reboot)."
        $script:RebootRequired = $true
    }
    catch {
        Write-Log "QMR registry failed: $_"
    }
}

# ==========================================
# OPTION 1 – Smart Setup
# ==========================================
function Run-SmartFirstTimeSetup {
    Write-Log "=== Running Smart First-Time Setup ==="

    Install-SyncroAgent

    if (Is-DellSystem) {
        Install-DellCommandUpdate
    } else {
        Write-Log "Non-Dell system. Skipping DCU."
    }

    Install-SoftwarePackages
    Set-Hostname
    Enable-QuickMachineRecovery
    Install-WindowsUpdates-GetMeUpToDate
    Check-SecureBootStatus
    Run-MemoryDiagnostic

    Write-Log "=== Smart Setup Complete ==="

    if ($script:RebootRequired) {
        Write-Log "System will reboot in 10 seconds..."
        shutdown /r /t 10
    } else {
        Write-Log "Reboot not required."
    }
}

# Menu
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

# Menu handler
function MenuSelection {
    param ([int]$selection)

    switch ($selection) {
        1 { Run-SmartFirstTimeSetup }
        2 { Enable-BitLockerDrive }
        3 { Run-MemoryDiagnostic }
        4 { Reboot-ToUEFI }
        5 {
            Write-Log "Performing cleanup..."
            Remove-DesktopShortcut -ShortcutName "Computek Setup Script"
            Write-Log "Exiting..."
            exit
        }
        default { Write-Log "Invalid choice." }
    }
}

# Main
if (-not ([Security.Principal.WindowsPrincipal] `
          ([Security.Principal.WindowsIdentity]::GetCurrent())
          ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {

    Write-Log "Script requires admin rights."
    exit 1
}

do {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-5) [Default 1]"

    if ($choice -notmatch '^[1-5]$') { $choice = 1 }

    MenuSelection -selection $choice
    Pause
} while ($true)
