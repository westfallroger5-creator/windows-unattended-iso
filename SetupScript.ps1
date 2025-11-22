# ========================
# Computek Autounattend Startup Loader
# ========================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ------------------------
# GitHub Variables
# ------------------------
$FolderName = "Computek"
$NewFolderPath = Join-Path -Path $env:APPDATA -ChildPath $FolderName

$AccessToken = "github_"+"pat_"+"11BX3AQ5Q0P0DvjxkGvNcM_BMfcbln9ETJL9Z7RXI8Aky1OJoFGtRCjRTSsVT9zPuiSS6NKIF2ZqAI5jLg"
$RepoOwner = "westfallroger5-creator"
$RepoName  = "windows-unattended-iso"
$Branch    = "main"
$BaseUrl   = "https://api.github.com/repos/$RepoOwner/$RepoName/contents"

$Headers = @{
    Authorization = "token $AccessToken"
    "User-Agent" = "PowerShell"
}

# ------------------------
# Ensure Computek folder exists
# ------------------------
if (-not (Test-Path -Path $NewFolderPath)) {
    New-Item -ItemType Directory -Path $NewFolderPath | Out-Null
}

# ------------------------
# Download target files
# ------------------------
$FileList = @("Computek.ico", "GetSetupScript.ps1", "Wallpaper.bmp", "NewSystemSetup.ps1")

Write-Host "Downloading files from GitHub..."
$Files = Invoke-RestMethod -Uri ($BaseUrl + "?ref=$Branch") -Headers $Headers

foreach ($File in $Files) {
    if ($File.type -eq "file" -and $File.name -in $FileList) {
        $OutFile = Join-Path $NewFolderPath $File.name
        Invoke-RestMethod -Uri $File.download_url -Headers $Headers -OutFile $OutFile
        Write-Host "Downloaded: $File.name"
    }
}

# ------------------------
# Create Startup entry for ALL future new users
# ------------------------
$DefaultStartup = "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

if (!(Test-Path $DefaultStartup)) {
    New-Item -ItemType Directory -Path $DefaultStartup -Force | Out-Null
}

$ShortcutName  = "Computek Setup.lnk"
$ShortcutPath  = Join-Path $DefaultStartup $ShortcutName
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# Use %APPDATA% so it resolves for whichever user logs in
$ShortcutArgs = "-ExecutionPolicy Bypass -File `"%APPDATA%\Computek\GetSetupScript.ps1`""

# ------------------------
# Create Shortcut
# ------------------------
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut     = $WScriptShell.CreateShortcut($ShortcutPath)

$Shortcut.TargetPath   = $PowerShellExe
$Shortcut.Arguments    = $ShortcutArgs
$Shortcut.IconLocation = "%APPDATA%\Computek\Computek.ico"
$Shortcut.WindowStyle  = 1
$Shortcut.Save()

Write-Host "Startup shortcut created in Default profile."

# ------------------------
# Done
# ------------------------
Write-Host "Computek Autoload setup complete."
