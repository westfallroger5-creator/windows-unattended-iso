##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1 does the full setup, auto-detects Dell, triggers Windows Updates via supported native 25H2 methods,
#   enables QMR (registry), logs secure boot, schedules memtest, and reboots at the end.
# - Option 2 keeps BitLocker manual.
# - Cleanup happens ONLY on Exit (Option 5). Active Hours are never modified.
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
Write-Host "v2.4 (Smart Auto Mode + Native 25H2 Update Engine + QMR Registry Enable)"

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
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path -Path $desktopPath -ChildPath "$ShortcutName.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Write-Log "Shortcut '$ShortcutName' deleted from the desktop."
    } else {
        Write-Log "Shortcut '$ShortcutName' not found on the desktop."
    }
}

function Install-SyncroAgent {
    Write-Log "Installing Syncro Agent..."
    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $Url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $SavePath = "C:\Windows\Temp\SyncroSetup.exe"
        $FileArguments = "--console --customerid 1362064 --folderid 4238852"

        try {
            Invoke-WebRequest -Uri $Url -OutFile $SavePath -UseBasicParsing
            Start-Process -FilePath $SavePath -ArgumentList $FileArguments -Wait
            Write-Log "Syncro Agent installed successfully."
        } catch {
            Write-Log "Failed to install Syncro Agent: $_"
        }
    } else {
        Write-Log "Syncro Agent is already installed."
    }
}

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

function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        Write-Log "Could not determine manufacturer: $_"
        return $false
    }
}

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

function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Starting Windows Updates using supported 25H2 native methods..."

    try {
        Write-Log "Resetting Windows Update components..."
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service bits -Force -ErrorAction SilentlyContinue

        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue

        Start-Service wuauserv -ErrorAction SilentlyContinue
        Start-Service bits -ErrorAction SilentlyContinue
        Write-Log "Windows Update components reset."

        Write-Log "Triggering StartScan..."
        Start-Process "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden

        Write-Log "Triggering ScanInstallWait (25H2 method)..."
        Start-Process "UsoClient.exe" -ArgumentList "ScanInstallWait" -WindowStyle Hidden

        Write-Log "Triggering StartInteractiveScan..."
        Start-Process "UsoClient.exe" -ArgumentList "StartInteractiveScan" -WindowStyle Hidden

        Write-Log "Attempting ResumeUpdate..."
        Start-Process "UsoClient.exe" -ArgumentList "ResumeUpdate" -WindowStyle Hidden

        Write-Log "Updates requested. Windows will continue in background through reboot."
        $script:RebootRequired = $true
    }
    catch {
        Write-Log "Windows Update trigger failed: $_"
    }
}

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

function Reboot-ToUEFI {
    Write-Host "Rebooting into UEFI Firmware Settings..." -ForegroundColor Cyan
    try {
        Shutdown.exe /r /fw /t 0
        Write-Log "System restarting to UEFI firmware settings."
    } catch {
        Write-Log "Failed to restart to UEFI firmware settings."
    }
}

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
        Write-Log "QMR will appear ENABLED after updates + final reboot."
        $script:RebootRequired = $true

    } catch {
        Write-Log "Error enabling Quick Machine Recovery: $_"
    }
}

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

    Write-Log "=== Smart Setup Complete ==="

    if ($script:RebootRequired) {
        Write-Log "Reboot required. System will reboot in 10 seconds..."
        shutdown /r /t 10
    } else {
        Write-Log "No reboot required. You may reboot manually when convenient."
    }
}

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
    Write-Host "Press Enter to select the default option (1) or choose another option."
}

function MenuSelection {
    param ([int]$selection)
    switch ($selection) {
        1  { Run-SmartFirstTimeSetup }
        2  { Write-Log "Enabling BitLocker on C: drive..."; Enable-BitLockerDrive }
        3  { Write-Log "Running Windows Memory Diagnostic..."; Run-MemoryDiagnostic }
        4  { Write-Log "Rebooting to UEFI Firmware Settings..."; Reboot-ToUEFI }
        5  {
            Write-Log "Performing cleanup tasks before exit..."
            try {
                Remove-DesktopShortcut -ShortcutName "Computek Setup Script"
            } catch {
                Write-Log "Cleanup encountered an error: $_"
            }
            Write-Log "Exiting script..."
            exit
        }
        default { Write-Log "Invalid selection. Please choose a valid option." }
    }
}

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
