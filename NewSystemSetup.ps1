##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1 does the full setup, auto-detects Dell, runs updates, enables QMR, logs secure boot, schedules memtest, reboots at the end.
# - Option 2 keeps BitLocker manual.
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
Write-Host "v2.0 (Smart Auto Mode + 25H2 Quick Machine Recovery support)"

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

# Function: Remove desktop shortcut
function Remove-DesktopShortcut {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ShortcutName
    )
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path -Path $desktopPath -ChildPath "$ShortcutName.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Write-Log "Shortcut '$ShortcutName' deleted from the desktop."
    } else {
        Write-Log "Shortcut '$ShortcutName' not found on the desktop."
    }
}

# Function: Install Syncro Agent
function Install-SyncroAgent {
    Write-Log "Installing Syncro Agent..."
    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $Url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $SavePath = "C:\Windows\Temp\SyncroSetup.exe"
        $FileArguments = "--console --customerid 1362064 --folderid 4238852"
        Invoke-WebRequest -Uri $Url -OutFile $SavePath
        Start-Process -FilePath $SavePath -ArgumentList $FileArguments -Wait
        Write-Log "Syncro Agent installed successfully."
    } else {
        Write-Log "Syncro Agent is already installed."
    }
}

# Function: Ensure Chocolatey Installed
function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey not found. Installing..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed successfully."
        } catch {
            Write-Log "Failed to install Chocolatey: $_"
            throw
        }
    } else {
        Write-Log "Chocolatey is already installed."
    }
}

# Function: Detect if system is Dell
function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        Write-Log "Could not determine manufacturer: $_"
        return $false
    }
}

# Function: Install Dell Command | Update (Dell only)
function Install-DellCommandUpdate {
    Write-Log "Dell detected. Installing Dell Command | Update..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install dellcommandupdate -y" -NoNewWindow -Wait
        Write-Log "Dell Command | Update installed successfully."
        return $true
    } catch {
        Write-Log "Failed to install Dell Command | Update: $_"
        return $false
    }
}

# Function: Install software packages
function Install-SoftwarePackages {
    Write-Log "Installing software packages via Chocolatey..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install googlechrome adobereader -y" -NoNewWindow -Wait
        Write-Log "Software packages installed successfully."
        return $true
    } catch {
        Write-Log "Failed to install software packages: $_"
        return $false
    }
}

# Function: Configure hostname (NO reboot here)
function Set-Hostname {
    Write-Log "Setting system hostname..."
    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $newHostname = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $newHostname) {
        try {
            Rename-Computer -NewName $newHostname -Force
            Write-Log "Hostname set to $newHostname. (Reboot required later)"
            $script:RebootRequired = $true
        } catch {
            Write-Log "Failed to rename computer: $_"
        }
    } else {
        Write-Log "Hostname is already set to $newHostname."
    }
}

# Function: Install Windows updates (Get me up to date) - NO reboot here
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Preparing Windows Update environment..."

    try {
        # Reset WU components to prevent corrupt metadata issues
        Write-Log "Resetting Windows Update components..."
        Stop-Service wuauserv -Force
        Stop-Service bits -Force

        Remove-Item -Recurse -Force "C:\Windows\SoftwareDistribution\Download\*" -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force "C:\Windows\SoftwareDistribution\DataStore\*" -ErrorAction SilentlyContinue

        Start-Service wuauserv
        Start-Service bits
        Write-Log "Windows Update components reset."

        # Ensure PSWindowsUpdate is available
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        }

        Import-Module PSWindowsUpdate

        Write-Log "Scanning for updates..."
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot | Out-Null

        # Check reboot-needed state
        try {
            $rebootStatus = Get-WURebootStatus -Silent
            if ($rebootStatus.RebootRequired) {
                Write-Log "Windows Update requires a reboot."
                $script:RebootRequired = $true
            } else {
                Write-Log "Windows Update completed without requiring reboot."
            }
        } catch {
            Write-Log "Could not read reboot status. Reboot may be required."
            $script:RebootRequired = $true
        }

    } catch {
        Write-Log "Error installing updates: $_"
    }
}

# Function: Enable BitLocker (Manual option remains)
function Enable-BitLockerDrive {
    param (
        [string]$DriveLetter = "C:",
        [string]$RecoveryKeyPath = "C:\BitLockerRecoveryKey.txt"
    )
    try {
        if (Get-BitLockerVolume -MountPoint $DriveLetter | Where-Object { $_.ProtectionStatus -eq "On" }) {
            Write-Log "BitLocker already enabled on $DriveLetter."
        } else {
            Enable-BitLocker -MountPoint $DriveLetter -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryKeyPath $RecoveryKeyPath -TpmProtector
            Write-Log "BitLocker enabled on $DriveLetter. Recovery key saved at $RecoveryKeyPath."
        }
    } catch {
        Write-Log "Failed to enable BitLocker: $_"
    }
}

# Function: Run Windows Memory Diagnostic (scheduled, no reboot here)
function Run-MemoryDiagnostic {
    Write-Log "Scheduling Windows Memory Diagnostic test..."
    try {
        Start-Process -FilePath "mdsched.exe" -ArgumentList "/restart" -WindowStyle Hidden
        Write-Log "Memory Diagnostic scheduled for next reboot."
        $script:RebootRequired = $true
    } catch {
        Write-Log "Failed to schedule Memory Diagnostic. Ensure administrative privileges."
    }
}

# Function: Check Secure Boot (logged in Option 1)
function Check-SecureBootStatus {
    try {
        $secureBootState = Confirm-SecureBootUEFI
        if ($secureBootState) {
            Write-Log "Secure Boot is ENABLED."
        } else {
            Write-Log "Secure Boot is DISABLED."
        }
    } catch {
        Write-Log "Secure Boot not supported or not in UEFI mode."
    }
}

# Function: Reboot to UEFI (manual option)
function Reboot-ToUEFI {
    Write-Host "Rebooting into UEFI Firmware Settings..." -ForegroundColor Cyan
    try {
        Shutdown.exe /r /fw /t 0
        Write-Log "System restarting to UEFI firmware settings."
    } catch {
        Write-Log "Failed to restart to UEFI firmware settings."
    }
}

# Function: Enable Quick Machine Recovery (25H2+) - no reboot required
function Enable-QuickMachineRecovery {
    Write-Log "Applying Quick Machine Recovery registry settings..."

    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"

        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        Set-ItemProperty -Path $regPath -Name "QuickRecoveryEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name "ContinueSearchingEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name "LookForSolutionEvery" -Value 0 -Type DWord
        Set-ItemProperty -Path $regPath -Name "RestartEvery" -Value 0 -Type DWord

        Write-Log "Quick Machine Recovery registry configuration applied."
        Write-Log "QMR will appear ENABLED after the final reboot."

        $script:RebootRequired = $true

    } catch {
        Write-Log "Error enabling Quick Machine Recovery: $_"
    }
}


# ==========================================
# OPTION 1: SMART FIRST-TIME SETUP
# ==========================================
function Run-SmartFirstTimeSetup {
    Write-Log "=== Running Smart First-Time Setup Routine ==="

    Install-SyncroAgent

    if (Is-DellSystem) {
        Install-DellCommandUpdate | Out-Null
    } else {
        Write-Log "Non-Dell system detected. Skipping Dell Command | Update."
    }

    Install-SoftwarePackages | Out-Null
    Set-Hostname
    Enable-QuickMachineRecovery
    Install-WindowsUpdates-GetMeUpToDate
    Check-SecureBootStatus
    Run-MemoryDiagnostic

    # Cleanup tasks previously on Exit
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "SmartActiveHoursState" -Value 1 -Force
        Write-Log "Active hours restored to default behavior."
    } catch {
        Write-Log "Could not restore active hours setting: $_"
    }

    Remove-DesktopShortcut -ShortcutName "Computek Setup Script"

    Write-Log "=== Smart Setup Complete ==="

    if ($script:RebootRequired) {
        Write-Log "Reboot required. System will reboot in 10 seconds..."
        shutdown /r /t 10
    } else {
        Write-Log "No reboot required. You may reboot manually when convenient."
    }
}

# Function: Display the main menu
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. Enable BitLocker on C:"
    Write-Host "3. Run Windows Memory Diagnostic (Manual)"
    Write-Host "4. Reboot to UEFI Firmware Settings"
    Write-Host "5. Exit"
    Write-Host "=========================================="
    Write-Host "Press Enter to select the default option (1) or choose another option."
}

# ==========================================
# MENU HANDLER
# ==========================================
function MenuSelection {
    param ([int]$selection)
    switch ($selection) {
        1  { Run-SmartFirstTimeSetup }
        2  { Write-Log "Enabling BitLocker on C: drive..."; Enable-BitLockerDrive }
        3  { Write-Log "Running Windows Memory Diagnostic..."; Run-MemoryDiagnostic }
        4  { Write-Log "Rebooting to UEFI Firmware Settings..."; Reboot-ToUEFI }
        5  { Write-Log "Exiting script..."; exit }
        default { Write-Log "Invalid selection. Please choose a valid option." }
    }
}

# ==========================================
# MAIN EXECUTION
# ==========================================
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Log "Script requires administrator privileges. Exiting."
    exit 1
}

do {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-5) [Default: 1]"

    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 5) {
        $choice = [int]$choice
    } else {
        $choice = 1
    }

    MenuSelection -selection $choice
    Pause
} while ($true)
