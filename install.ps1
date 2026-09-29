# Warden setup script
Write-Host "Installing Warden..." -ForegroundColor Cyan

$UvBinPath = Join-Path $HOME ".local\bin"

# uv is installed at a pinned version. The minimum is the first uv that reads a duration such as
# "7 days" for --exclude-newer. install.sh pins the same version.
$UvVersion = "0.12.20"
$UvMinVersion = [version]"0.9.17"

if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Missing requirement: Docker. Please install it first."
    exit 1
}

if (!(Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing uv..."
    & powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/$UvVersion/install.ps1 | iex"
}

$env:Path = "$UvBinPath;$env:Path"

Write-Host "[*] Checking dependency tools..."
if (!(Get-Command trivy -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing Trivy..."
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop install trivy
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install trivy -y
    } else {
        Write-Warning "Neither Scoop nor Chocolatey found. Please install Trivy manually: https://trivy.dev"
    }
}

if (!(Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing Gitleaks..."
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop install gitleaks
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install gitleaks -y
    } else {
        Write-Warning "Neither Scoop nor Chocolatey found. Please install Gitleaks manually: https://github.com/gitleaks/gitleaks"
    }
}

# `uv tool install` ignores this repository's uv.lock and its [tool.uv] settings, including the
# seven-day cooldown on new releases, so the cooldown is passed explicitly. A uv older than
# $UvMinVersion rejects `--exclude-newer "7 days"` with a bare parse error, so say what is
# wrong and what to do before it gets that far.
if ((& uv --version) -match '(\d+\.\d+\.\d+)') {
    $UvInstalled = [version]$Matches[1]
    if ($UvInstalled -lt $UvMinVersion) {
        Write-Error "uv $UvInstalled is too old: this install needs uv $UvMinVersion or newer. Update it (https://docs.astral.sh/uv/getting-started/installation/) and run this script again."
        exit 1
    }
}

Write-Host "[*] Installing Warden with uv..."
uv python install 3.11
uv tool install --force --python 3.11 --exclude-newer "7 days" -e $PSScriptRoot

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$UvBinPath*") {
    Write-Host "[*] Adding '$UvBinPath' to your User PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$UvBinPath", "User")
    Write-Host "Added. Restart your terminal to use the command 'warden'." -ForegroundColor Green
} else {
    Write-Host "uv tool bin directory is already on your PATH." -ForegroundColor Green
}
