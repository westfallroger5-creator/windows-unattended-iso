##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (v3.1)
# - Option 1 (Default): Full smart setup
#     * Starts Windows Updates EARLY (async) and opens WU UI for live progress
#     * Installs Syncro Agent
#     * Auto-detects Dell and installs Dell Command | Update (if Dell)
#     * Starts Chocolatey installs for Chrome + Adobe Reader ASYNC (does not wait)
#     * Sets hostname (no reboot forced)
#     * Enables Quick Machine Recovery (registry)
#     * Checks Secure Boot (logs to screen only)
# - Option 2: Restart computer
# - Option 3: Exit and cleanup
# Notes:
# - No BitLocker, no Memory Diagnostic, no UEFI reboot.
# - No file logging.
# - No forced reboot in Option 1; installs continue in background.
##########################################################################################################################################################

function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

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
Write-Host "Welcome to the Compu-TEK Setup Tool!"
Write-Host "v3.1 (Parallel Windows Updates + Parallel Chocolatey + 3-Option Menu)"
Write-Host ""

# -----------------------------
# Utility: Remove desktop shortcut (cleanup on exit)
# -----------------------------
function Remove-DesktopShortcut {
    param ([string]$ShortcutName)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $path = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $path) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
        Write-Host "Cleanup: Removed desktop shortcut '$ShortcutName'."
    }
}

# -----------------------------
# Install Syncro Agent (waits for installer only)
# -----------------------------
function Install-SyncroAgent {
    Write-Host "Installing Syncro Agent..."
    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $url  = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $path = "C:\Windows\Temp\SyncroSetup.exe"
        $args = "--console --customerid 1362064 --folderid 4238852"
        try {
            Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing
            Start-Process $path -ArgumentList $args -Wait
            Write-Host "Syncro Agent installed."
        } catch {
            Write-Host "WARNING: Syncro install failed. Continuing..."
        }
    } else {
        Write-Host "Syncro Agent already installed."
    }
}

# -----------------------------
# Ensure Chocolatey Installed (sync install, then background packages)
# -----------------------------
function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey not found. Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Host "Chocolatey installed."
        } catch {
            Write-Host "WARNING: Chocolatey install failed. Continuing without app installs..."
            return $false
        }
    } else {
        Write-Host "Chocolatey already installed."
    }
    return $true
}

# -----------------------------
# Detect Dell
# -----------------------------
function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    } catch {
        return $false
    }
}

# -----------------------------
# Dell Command | Update (Dell only)
# -----------------------------
function Install-DellCommandUpdate {
    Write-Host "Dell detected. Starting Dell Command | Update install..."
    try {
        if (Ensure-Chocolatey) {
            # Run sync because it's small and useful before driver/firmware updates
            Start-Process "choco" -ArgumentList "install dellcommandupdate -y --no-progress" -NoNewWindow -Wait
            Write-Host "Dell Command | Update installed."
        } else {
            Write-Host "Skipping Dell Command | Update (Chocolatey missing)."
        }
    } catch {
        Write-Host "WARNING: Dell Command | Update install failed. Continuing..."
    }
}

# -----------------------------
# Software installs via Chocolatey (ASYNC, never waits)
# -----------------------------
function Install-SoftwarePackages {
    Write-Host "Starting background installs (Chrome + Adobe Reader)..."
    if (-not (Ensure-Chocolatey)) {
        Write-Host "Skipping software installs (Chocolatey missing)."
        return
    }

    try {
       function Install-SoftwarePackages {
    Write-Host "Installing Chrome + Adobe Reader (visible, blocking)..."

    if (-not (Ensure-Chocolatey)) {
        Write-Host "Skipping software installs (Chocolatey missing)."
        return
    }

    try {
        Write-Host "`n=== Installing Google Chrome ==="
        Start-Process "choco" -ArgumentList "install googlechrome -y" -NoNewWindow -Wait

        Write-Host "`n=== Installing Adobe Reader ==="
        Start-Process "choco" -ArgumentList "install adobereader -y" -NoNewWindow -Wait

        Write-Host "`nAll Chocolatey installs completed successfully."
    }
    catch {
        Write-Host "WARNING: One or more installs failed."
    }
}
        Write-Host "Chocolatey installs queued in background."
    } catch {
        Write-Host "WARNING: Failed to start Chocolatey installs. Continuing..."
    }
}

# -----------------------------
# Hostname (no reboot)
# -----------------------------
function Set-Hostname {
    Write-Host "Configuring hostname..."
    try {
        $brand  = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
        $serial = (Get-CimInstance Win32_BIOS).SerialNumber
        $newName = "$brand-$serial"

        if ($env:COMPUTERNAME -ne $newName) {
            Rename-Computer -NewName $newName -Force
            Write-Host "Hostname set to: $newName (reboot recommended later)."
        } else {
            Write-Host "Hostname already correct."
        }
    } catch {
        Write-Host "WARNING: Hostname change failed. Continuing..."
    }
}

# -----------------------------
# Windows Updates (ASYNC) + open UI
# -----------------------------
function Install-WindowsUpdates-Async {
    Write-Host "Starting Windows Updates with visible UI..."

    try {
        # Open Windows Update settings UI
        Start-Process "ms-settings:windowsupdate"

        Start-Sleep -Seconds 2

        # Trigger scan *in the visible interface*
        Start-Process "control.exe" -ArgumentList "/name Microsoft.WindowsUpdate"

        Write-Host "Windows Update UI opened and scanning visibly."
    }
    catch {
        Write-Host "WARNING: Failed to show Windows Update UI. Continuing..."
    }
}

# -----------------------------
# Secure Boot check (screen only)
# -----------------------------
function Check-SecureBootStatus {
    try {
        $state = Confirm-SecureBootUEFI
        if ($state) {
            Write-Host "Secure Boot: ENABLED"
        } else {
            Write-Host "Secure Boot: DISABLED"
        }
    } catch {
        Write-Host "Secure Boot: Not supported or not UEFI."
    }
}

# -----------------------------
# Quick Machine Recovery (registry)
# -----------------------------
function Enable-QuickMachineRecovery {
    Write-Host "Applying Quick Machine Recovery registry keys..."
    try {
        $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability\QuickRecovery"
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }

        Set-ItemProperty -Path $reg -Name "QuickRecoveryEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $reg -Name "ContinueSearchingEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $reg -Name "LookForSolutionEvery" -Value 0 -Type DWord
        Set-ItemProperty -Path $reg -Name "RestartEvery" -Value 0 -Type DWord

        Write-Host "QMR keys applied. Toggle should show after reboot."
    } catch {
        Write-Host "WARNING: QMR registry set failed. Continuing..."
    }
}

# -----------------------------
# OPTION 1: Smart First-Time Setup (parallel updates + parallel installs)
# -----------------------------
function Run-SmartFirstTimeSetup {
    Write-Host ""
    Write-Host "===== Smart Auto Setup START ====="

    # Start updates first so they run in tandem
    Install-WindowsUpdates-Async

    # Continue with other tasks
    Install-SyncroAgent

    if (Is-DellSystem) {
        Install-DellCommandUpdate
    } else {
        Write-Host "Non-Dell system detected. Skipping Dell Command | Update."
    }

    # Queue software installs in background and continue immediately
    Install-SoftwarePackages

    Set-Hostname
    Enable-QuickMachineRecovery
    Check-SecureBootStatus

    Write-Host "===== Smart Auto Setup COMPLETE ====="
    Write-Host "Background tasks still running: Windows Updates + Chocolatey installs."
    Write-Host "Reboot manually when Windows Update finishes."
    Write-Host ""
}

# -----------------------------
# MENU
# -----------------------------
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. Restart Computer"
    Write-Host "3. Exit and Cleanup"
    Write-Host "=========================================="
    Write-Host "Press Enter for default (1)."
}

function MenuSelection {
    param([int]$selection)
    switch ($selection) {
        1 { Run-SmartFirstTimeSetup }
        2 { Write-Host "Restarting now..."; shutdown.exe /r /t 0 }
        3 { Write-Host "Cleaning up and exiting..."; Remove-DesktopShortcut "Computek Setup Script"; exit }
        default { Write-Host "Invalid selection." }
    }
}

# -----------------------------
# MAIN LOOP
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator required. Exiting."
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Enter choice (1-3) [Default = 1]"
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 3) {
        $choice = [int]$choice
    } else {
        $choice = 1
    }
    MenuSelection -selection $choice
    Pause
} while ($true)
