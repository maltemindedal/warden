# Warden setup script
Write-Host "Installing Warden..." -ForegroundColor Cyan

$UvBinPath = Join-Path $HOME ".local\bin"

if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Missing requirement: Docker. Please install it first."
    exit 1
}

if (!(Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing uv..."
    & powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"
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

Write-Host "[*] Installing Warden with uv..."
uv python install 3.11
uv tool install --force --python 3.11 -e $PSScriptRoot

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$UvBinPath*") {
    Write-Host "[*] Adding '$UvBinPath' to your User PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$UvBinPath", "User")
    Write-Host "Added. Restart your terminal to use the command 'warden'." -ForegroundColor Green
} else {
    Write-Host "uv tool bin directory is already on your PATH." -ForegroundColor Green
}
