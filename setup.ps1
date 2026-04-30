# Krypta Setup Script
# This script ensures Python 3.14 and the 'cryptography' library are installed.

Write-Host "--- Krypta Setup ---" -ForegroundColor Cyan

# Check for Python
try {
    $pythonVersion = & python --version 2>$null
    if ($pythonVersion -match "Python 3") {
        Write-Host "[OK] Python is already installed: $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "[!] Python not found or not in PATH. Downloading installer..." -ForegroundColor Yellow
    $url = "https://www.python.org/ftp/python/3.14.0/python-3.14.0a4-amd64.exe" # Example link, version might vary
    $dest = "$env:TEMP\python_installer.exe"
    Invoke-WebRequest -Uri $url -OutFile $dest
    Write-Host "[*] Running installer. Please follow the instructions and check 'Add Python to PATH'." -ForegroundColor Cyan
    Start-Process -FilePath $dest -Wait
}

# Install cryptography library
Write-Host "[*] Installing 'cryptography' library..." -ForegroundColor Cyan
& python -m pip install cryptography

Write-Host "--- Setup Complete! You can now run Krypta. ---" -ForegroundColor Green
Pause
