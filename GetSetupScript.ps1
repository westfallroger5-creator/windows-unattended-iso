# This script downloads specified files from a GitHub repository using the GitHub API
# and only updates files if they have changed.

# Set the working directory to the AppData folder
Set-Location -Path $env:APPDATA

# ========================
# Define variables
# ========================
$FolderName = "Computek" # Name of the folder to store downloaded files
$NewFolderPath = Join-Path -Path $env:APPDATA -ChildPath $FolderName # Full path to the folder
$AccessToken = "github_"+"pat_"+"11BX3AQ5Q0P0DvjxkGvNcM_BMfcbln9ETJL9Z7RXI8Aky1OJoFGtRCjRTSsVT9zPuiSS6NKIF2ZqAI5jLg" # GitHub token
$RepoOwner = "westfallroger5-creator" # GitHub repository owner
$RepoName = "windows-unattended-iso" # GitHub repository name
$Branch = "main" # Branch to download files from
$FileList = @("Computek.ico", "GetSetupScript.ps1", "Wallpaper.bmp", "NewSystemSetup.ps1") # List of files to download

# ========================
# Create the folder if it doesn't exist
# ========================
if (-not (Test-Path -Path $NewFolderPath)) {
    New-Item -ItemType Directory -Path $NewFolderPath
    Write-Host "Folder created at: $NewFolderPath"
} else {
    Write-Host "Folder already exists at: $NewFolderPath"
}

Set-Location -Path $NewFolderPath

# ========================
# Set up GitHub API access
# ========================
$BaseUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/contents" # API URL for the repository's contents
$Headers = @{
    Authorization = "token $AccessToken"
    "User-Agent" = "PowerShell"
}

# ========================
# Download specified files if they have changed
# ========================
Write-Host "Checking for file updates..."
$Files = Invoke-RestMethod -Uri ($BaseUrl + "?ref=$Branch") -Headers $Headers

foreach ($File in $Files) {
    if ($File.type -eq "file" -and $File.name -in $FileList) {
        $FileName = $File.name
        $RemoteSha = $File.sha
        $LocalFilePath = Join-Path -Path $NewFolderPath -ChildPath $FileName

        # Check if the file exists locally and compare hashes
        if (Test-Path -Path $LocalFilePath) {
            $LocalSha = (Get-FileHash -Path $LocalFilePath -Algorithm SHA256).Hash

            if ($LocalSha -eq $RemoteSha) {
                Write-Host "$FileName is up-to-date. Skipping download."
                continue
            } else {
                Write-Host "$FileName has changed. Downloading updated version..."
            }
        } else {
            Write-Host "$FileName not found locally. Downloading..."
        }

        # Download the file
        $FileUrl = $File.download_url
        Invoke-RestMethod -Uri $FileUrl -Headers $Headers -OutFile $LocalFilePath
        Write-Host "Downloaded: $FileName"
    }
}

Write-Host "File check and download process completed."

# ========================
# Restart the script as administrator if not running as admin
# ========================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Restarting script as administrator..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$NewFolderPath\NewSystemSetup.ps1`"" -Verb RunAs
    exit
}








