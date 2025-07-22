# OMAP Build Script for Windows
# This script handles Go installation and building the OMAP scanner

Write-Host "OMAP - Advanced Network Scanner Build Script" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# Check if Go is installed
$goInstalled = $false
try {
    $goVersion = go version 2>$null
    if ($goVersion) {
        Write-Host "Go is already installed: $goVersion" -ForegroundColor Green
        $goInstalled = $true
    }
} catch {
    Write-Host "Go is not installed" -ForegroundColor Yellow
}

if (-not $goInstalled) {
    Write-Host "Installing Go..." -ForegroundColor Yellow
    
    # Download and install Go
    $goVersion = "1.21.5"
    $goUrl = "https://golang.org/dl/go$goVersion.windows-amd64.msi"
    $goInstaller = "$env:TEMP\go$goVersion.windows-amd64.msi"
    
    Write-Host "Downloading Go $goVersion..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $goUrl -OutFile $goInstaller -UseBasicParsing
        Write-Host "Installing Go..." -ForegroundColor Yellow
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $goInstaller, "/quiet" -Wait
        
        # Add Go to PATH for current session
        $env:PATH += ";C:\Program Files\Go\bin"
        
        Write-Host "Go installation completed!" -ForegroundColor Green
        Write-Host "Please restart your terminal or add C:\Program Files\Go\bin to your PATH" -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to download/install Go. Please install manually from https://golang.org/dl/" -ForegroundColor Red
        exit 1
    }
}

# Build the project
Write-Host "Building OMAP..." -ForegroundColor Yellow

try {
    # Initialize go modules if needed
    if (-not (Test-Path "go.sum")) {
        Write-Host "Initializing Go modules..." -ForegroundColor Yellow
        go mod tidy
    }
    
    # Build for Windows
    Write-Host "Building Windows executable..." -ForegroundColor Yellow
    go build -ldflags "-s -w" -o omap.exe .
    
    if (Test-Path "omap.exe") {
        Write-Host "Build successful! Created omap.exe" -ForegroundColor Green
        
        # Show file size
        $fileSize = (Get-Item "omap.exe").Length / 1MB
        Write-Host "Executable size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Green
        
        # Test basic functionality
        Write-Host "Testing basic functionality..." -ForegroundColor Yellow
        .\omap.exe --help
        
    } else {
        Write-Host "Build failed - executable not created" -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "Build failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "\nBuild completed successfully!" -ForegroundColor Green
Write-Host "Usage examples:" -ForegroundColor Cyan
Write-Host "  .\omap.exe -t 127.0.0.1 -p 1-1000" -ForegroundColor White
Write-Host "  .\omap.exe -t 192.168.1.0/24 -p top-100 --os --sV" -ForegroundColor White
Write-Host "  .\omap.exe -t example.com -p 80,443 --plugins" -ForegroundColor White