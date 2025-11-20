##########################################################################################################################################################
# Description: This script automates the setup process for new systems, including software installation, updates, and system configuration.              #
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
Write-Host $asciiArt -ForegroundColor DarkBlue
Write-Host "Welcome to the System Management Script!"
Write-Host "v1.3 (with Windows 11 25H2 Quick Machine Recovery support)"

# Function: Display the main menu
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Dell Setup Routine (Default)"
    Write-Host "2. First Time Other Setup Routine"
    Write-Host "3. Upgrade to Windows Pro"
    Write-Host "4. Install All Windows Updates (Default)"
    Write-Host "5. Install All Windows Updates (Get me up to date)"
    Write-Host "6. Enable BitLocker on C:"
    Write-Host "7. Run Windows Memory Diagnostic"
    Write-Host "8. Check Secure Boot Status"
    Write-Host "9. Reboot to UEFI Firmware Settings"
    Write-Host "10. Enable Quick Machine Recovery (25H2 Feature)"
    Write-Host "11. Exit and Cleanup"
    Write-Host "=========================================="
    Write-Host "Press Enter to select the default option (1) or choose another option."
}

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

# Function: Configure hostname
function Set-Hostname {
    Write-Log "Setting system hostname..."
    $brand = ((Get-WmiObject Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber
    $newHostname = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $newHostname) {
        Rename-Computer -NewName $newHostname -Force -Restart
        Write-Log "Hostname set to $newHostname."
    } else {
        Write-Log "Hostname is already set to $newHostname."
    }
}

# Function: Install Windows updates
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Enabling 'Get me up to date' behavior for Windows Updates..."

    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        }

        Import-Module PSWindowsUpdate

        Write-Log "Disabling active hours..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "SmartActiveHoursState" -Value 0 -Force

        Write-Log "Scanning for available updates..."
        $Updates = Get-WindowsUpdate -AcceptAll -Install -Verbose

        if ($Updates) {
            Write-Log "Updates installed successfully. Rebooting if necessary..."
            Restart-Computer -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "No updates found or applicable."
        }
    } catch {
        Write-Log "Error installing updates: $_"
    }
}

# Function: Enable BitLocker
function Enable-BitLockerDrive {
    param (
        [string]$DriveLetter = "C:",
        [string]$RecoveryKeyPath = "C:\BitLockerRecoveryKey.txt"
    )
    if (Get-BitLockerVolume -MountPoint $DriveLetter | Where-Object { $_.ProtectionStatus -eq "On" }) {
        Write-Log "BitLocker already enabled on $DriveLetter."
    } else {
        Enable-BitLocker -MountPoint $DriveLetter -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryKeyPath $RecoveryKeyPath -TpmProtector
        Write-Log "BitLocker enabled on $DriveLetter. Recovery key saved at $RecoveryKeyPath."
    }
}

# Function: Run Windows Memory Diagnostic
function Run-MemoryDiagnostic {
    Write-Host "Scheduling Windows Memory Diagnostic test..."
    try {
        Start-Process -FilePath "mdsched.exe" -ArgumentList "/restart"
        Write-Log "Memory Diagnostic scheduled. The system will restart now."
    } catch {
        Write-Log "Failed to schedule Memory Diagnostic. Ensure administrative privileges."
    }
}

# Function: Check Secure Boot
function Check-SecureBootStatus {
    try {
        $secureBootState = Confirm-SecureBootUEFI
        if ($secureBootState) {
            Write-Host "Secure Boot is ENABLED." -ForegroundColor Green
        } else {
            Write-Host "Secure Boot is DISABLED." -ForegroundColor Red
        }
    } catch {
        Write-Host "Secure Boot not supported or not in UEFI mode." -ForegroundColor Yellow
    }
}

# Function: Reboot to UEFI
function Reboot-ToUEFI {
    Write-Host "Rebooting into UEFI Firmware Settings..." -ForegroundColor Cyan
    try {
        Shutdown.exe /r /fw /t 0
        Write-Log "System restarting to UEFI firmware settings."
    } catch {
        Write-Log "Failed to restart to UEFI firmware settings."
    }
}

# Function: Install Dell Command | Update
function Install-DellCommandUpdate {
    Write-Log "Checking if Chocolatey is installed..."
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey not found. Installing..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed successfully."
        } catch {
            Write-Log "Failed to install Chocolatey: $_"
            return $false
        }
    } else {
        Write-Log "Chocolatey is already installed."
    }

    Write-Log "Installing Dell Command | Update via Chocolatey..."
    try {
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
    Write-Log "Checking if Chocolatey is installed..."
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey not found. Installing..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed successfully."
        } catch {
            Write-Log "Failed to install Chocolatey: $_"
            return $false
        }
    } else {
        Write-Log "Chocolatey is already installed."
    }

    Write-Log "Installing software packages via Chocolatey..."
    try {
        Start-Process "choco" -ArgumentList "install googlechrome adobereader -y" -NoNewWindow -Wait
        Write-Log "Software packages installed successfully."
        return $true
    } catch {
        Write-Log "Failed to install software packages: $_"
        return $false
    }
}

# ==========================================
# NEW FUNCTION: Enable Quick Machine Recovery (25H2)
# ==========================================
function Enable-QuickMachineRecovery {
    Write-Log "Checking Windows version for Quick Machine Recovery support..."

    try {
        $osBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        $osBuildInt = [int]$osBuild

        if ($osBuildInt -lt 26100) {
            Write-Log "Quick Machine Recovery requires Windows 11 25H2 (build 26100 or later). Current build: $osBuildInt"
            return
        }

        Write-Log "Enabling Quick Machine Recovery feature..."
        Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:QuickMachineRecovery /All /Quiet /NoRestart" -Wait -NoNewWindow

        $feature = (dism /online /Get-FeatureInfo /FeatureName:QuickMachineRecovery | Select-String "State : Enabled")
        if ($feature) {
            Write-Log "✅ Quick Machine Recovery successfully enabled."
            Write-Host "Quick Machine Recovery is now active on this device." -ForegroundColor Green
        } else {
            Write-Log "⚠️  Could not verify Quick Machine Recovery enablement. A reboot may be required."
        }
    }
    catch {
        Write-Log "Error enabling Quick Machine Recovery: $_"
    }
}

# ==========================================
# MENU HANDLER
# ==========================================
function MenuSelection {
    param ([int]$selection)
    switch ($selection) {
        1  { Write-Log "Running First Time Dell Setup..."; Install-SyncroAgent; Install-DellCommandUpdate; Install-SoftwarePackages; Set-Hostname }
        2  { Write-Log "Running First Time Other Setup..."; Install-SyncroAgent; Install-SoftwarePackages; Set-Hostname }
        3  { Write-Log "Upgrading to Windows Pro..."; Get-BiosProductKeyAndActivate }
        4  { Write-Log "Installing all Windows updates..."; Install-WindowsUpdates }
        5  { Write-Log "Installing Windows updates with 'Get me up to date' feature..."; Install-WindowsUpdates-GetMeUpToDate }
        6  { Write-Log "Enabling BitLocker on C: drive..."; Enable-BitLockerDrive }
        7  { Write-Log "Running Windows Memory Diagnostic..."; Run-MemoryDiagnostic }
        8  { Write-Log "Checking Secure Boot status..."; Check-SecureBootStatus }
        9  { Write-Log "Rebooting to UEFI Firmware Settings..."; Reboot-ToUEFI }
        10 { Write-Log "Enabling Quick Machine Recovery feature..."; Enable-QuickMachineRecovery }
        11 { Write-Log "Exiting script and cleaning up..."; Remove-DesktopShortcut -ShortcutName "Computek Setup Script"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "SmartActiveHoursState" -Value 1 -Force; exit }
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
    $choice = Read-Host "Enter your choice (1-11) [Default: 1]"
    
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 11) {
        $choice = [int]$choice
    } else {
        $choice = 1
    }

    MenuSelection -selection $choice
    Pause
} while ($true)

