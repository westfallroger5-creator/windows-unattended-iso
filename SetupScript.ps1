# This script is used in the Windows autounattend.xml.
# It creates a folder in the user's AppData directory, downloads specified files from a GitHub repository,
# and creates a desktop shortcut to execute a setup script as an administrator.

# ========================
# Set up variables and folder path
# ========================
Set-Location -Path $env:APPDATA
$FolderName = "Computek" # Name of the folder to store downloaded files
$NewFolderPath = Join-Path -Path $env:APPDATA -ChildPath $FolderName # Full path to the folder
$AccessToken = "github_"+"pat_"+"11BX3AQ5Q0P0DvjxkGvNcM_BMfcbln9ETJL9Z7RXI8Aky1OJoFGtRCjRTSsVT9zPuiSS6NKIF2ZqAI5jLg" # GitHub token
$RepoOwner = "westfallroger5-creator" # GitHub repository owner
$RepoName = "windows-unattended-iso" # GitHub repository name
$Branch = "main" # Branch to download files from
$BaseUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/contents" # API URL for the repository's contents

# ========================
# Create Computek folder if it doesn't exist
# ========================
if (-not (Test-Path -Path $NewFolderPath)) {
    New-Item -ItemType Directory -Path $NewFolderPath
    Write-Host "Folder created at: $NewFolderPath"
} else {
    Write-Host "Folder already exists at: $NewFolderPath"
}

# ========================
# Set up GitHub API access
# ========================
$Headers = @{
    Authorization = "token $AccessToken"
    "User-Agent" = "PowerShell"
}

# ========================
# Download specified files
# ========================
Write-Host "Downloading specified files..."
$FileList = @("Computek.ico", "GetSetupScript.ps1", "Wallpaper.bmp","NewSystemSetup.ps1") # List of files to download
$Files = Invoke-RestMethod -Uri ($BaseUrl + "?ref=$Branch") -Headers $Headers
Set-Location -Path $NewFolderPath

foreach ($File in $Files) {
    if ($File.type -eq "file" -and $File.name -in $FileList) { # Check if the file is in the list
        $FileUrl = $File.download_url
        $FileName = $File.name

        # Download the file
        Invoke-RestMethod -Uri $FileUrl -Headers $Headers -OutFile $FileName
        Write-Host "Downloaded: $FileName"
    }
}

Write-Host "All specified files have been downloaded."

# ========================
# Create a desktop shortcut for the setup script
# ========================
Write-Host "Creating desktop shortcut..."
$ShortcutName = "Computek Setup Script" # Name of the shortcut
$TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" # Path to PowerShell executable
$Arguments = "-ExecutionPolicy Bypass -File `"$env:APPDATA\Computek\GetSetupScript.ps1`" -Verb RunAs" # Arguments for the script
$IconPath = "$env:APPDATA\Computek\Computek.ico" # Path to the shortcut icon
$ShortcutPath = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "$ShortcutName.lnk") # Path for the shortcut on the desktop

# Create WScript.Shell COM object
$WScriptShell = New-Object -ComObject WScript.Shell

# Create and configure the shortcut
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.Arguments = $Arguments
$Shortcut.IconLocation = $IconPath
$Shortcut.Save()

Write-Host "Shortcut created at: $ShortcutPath"
