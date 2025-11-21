##########################################################################################################################################################
# Description: Compu-TEK First-Time System Setup Tool (Smart Auto Mode)
# - Option 1: Full setup (Dell detection, Syncro install, software, hostname, QMR, Windows Updates with live UI)
# - Option 2: Restart computer
# - Option 3: Exit and cleanup
# - No BitLocker, no Memory Diagnostic, no UEFI reboot
# - No forced reboot. Tech decides when to restart.
##########################################################################################################################################################

function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Set-ConsoleColor 'green' 'white'

# Log folder
$LogDirectory = "$env:APPDATA\Computek"
$LogFile = "$LogDirectory\SetupLog.txt"
if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# ASCII Art
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
Write-Host "v3.0 (Clean 3-Option Menu + No MemTest + No BitLocker + No UEFI)"

###############################################################################################################
# Logging Function
###############################################################################################################
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $Entry
    Write-Host $Message
}

###############################################################################################################
# Remove Desktop Shortcut
###############################################################################################################
function Remove-DesktopShortcut {
    param ([string]$ShortcutName)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $path = Join-Path $desktop "$ShortcutName.lnk"
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Log "Removed desktop shortcut: $ShortcutName"
    }
}

###############################################################################################################
# Install Syncro
###############################################################################################################
function Install-SyncroAgent {
    Write-Log "Installing Syncro Agent..."

    if (-not (Get-Service -Name "Syncro" -ErrorAction SilentlyContinue)) {
        $url = "https://rmm.syncromsp.com/dl/rs/djEtMzEzMDA4ODgtMTc0MDA3NjY3NC02OTUzMi00MjM4ODUy"
        $installer = "C:\Windows\Temp\SyncroSetup.exe"
        $args = "--console --customerid 1362064 --folderid 4238852"

        try {
            Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
            Start-Process $installer -ArgumentList $args -Wait
            Write-Log "Syncro Agent installed."
        }
        catch { Write-Log "Syncro install failed: $_" }
    }
    else { Write-Log "Syncro already installed." }
}

###############################################################################################################
# Ensure Chocolatey Installed
###############################################################################################################
function Ensure-Chocolatey {
    if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installed."
        }
        catch { Write-Log "Chocolatey install error: $_" }
    }
    else { Write-Log "Chocolatey already installed." }
}

###############################################################################################################
# Detect Dell
###############################################################################################################
function Is-DellSystem {
    try {
        $mfg = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        return ($mfg -match "Dell")
    }
    catch { Write-Log "Manufacturer detection failed."; return $false }
}

###############################################################################################################
# Install Dell Command Update
###############################################################################################################
function Install-DellCommandUpdate {
    Write-Log "Installing Dell Command | Update..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install dellcommandupdate -y" -Wait
        Write-Log "Dell Command Update installed."
    }
    catch { Write-Log "Dell Command install failed: $_" }
}

###############################################################################################################
# Install Chrome + Adobe
###############################################################################################################
function Install-SoftwarePackages {
    Write-Log "Installing Chrome + Adobe Reader..."
    try {
        Ensure-Chocolatey
        Start-Process "choco" -ArgumentList "install googlechrome adobereader -y" -Wait
        Write-Log "Software installed."
    }
    catch { Write-Log "Software install failed: $_" }
}

###############################################################################################################
# Hostname
###############################################################################################################
function Set-Hostname {
    Write-Log "Configuring hostname..."

    $brand = ((Get-CimInstance Win32_ComputerSystem).Manufacturer -split ' ')[0]
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    $newName = "$brand-$serial"

    if ($env:COMPUTERNAME -ne $newName) {
        try {
            Rename-Computer -NewName $newName -Force
            Write-Log "Hostname changed to: $newName"
        }
        catch { Write-Log "Hostname change failed: $_" }
    }
    else {
        Write-Log "Hostname already correct."
    }
}

###############################################################################################################
# Native Windows Update + Open UI
###############################################################################################################
function Install-WindowsUpdates-GetMeUpToDate {
    Write-Log "Starting Windows Updates..."

    try {
        Start-Process UsoClient.exe -ArgumentList "StartScan" -WindowStyle Hidden
        Start-Process UsoClient.exe -ArgumentList "StartInstall" -WindowStyle Hidden
        Write-Log "Update scan + install triggered."

        Start-Process "ms-settings:windowsupdate"
        Write-Log "Opened Windows Update UI."

    }
    catch { Write-Log "Update error: $_" }
}

###############################################################################################################
# QMR Registry
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
}

###############################################################################################################
# FIRST TIME SETUP (Option 1)
###############################################################################################################
function Run-SmartFirstTimeSetup {
    Write-Log "===== Running Smart Auto Setup ====="

    Install-SyncroAgent

    if (Is-DellSystem) { Install-DellCommandUpdate }
    else { Write-Log "Non-Dell system detected. Skipping Dell tools." }

    Install-SoftwarePackages
    Set-Hostname
    Enable-QuickMachineRecovery
    Install-WindowsUpdates-GetMeUpToDate
    Check-SecureBootUEFI | Out-Null

    Write-Log "===== Setup Complete ====="
    Write-Host "`n>>> Setup finished. Review Windows Update progress, then reboot when ready."
}

###############################################################################################################
# MENU
###############################################################################################################
function Show-Menu {
    Write-Host "=========================================="
    Write-Host "       System Management Menu"
    Write-Host "=========================================="
    Write-Host "1. First Time Setup (Smart Auto Mode) [Default]"
    Write-Host "2. Restart Computer"
    Write-Host "3. Exit and Cleanup"
    Write-Host "=========================================="
}

function MenuSelection {
    param([int]$selection)

    switch ($selection) {
        1 { Run-SmartFirstTimeSetup }
        2 { Write-Log "Restarting..."; shutdown.exe /r /t 0 }
        3 { Remove-DesktopShortcut "Computek Setup Script"; Write-Log "Exiting."; exit }
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
    $choice = Read-Host "Enter choice (1-3) [Default = 1]"
    if ($choice -match '^\d+$') { $choice = [int]$choice } else { $choice = 1 }
    MenuSelection -selection $choice
    Pause
} while ($true)
