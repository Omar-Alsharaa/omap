#!/usr/bin/env pwsh
# OMAP Web Interface Build Script
# This script builds the React web interface for OMAP

Write-Host "OMAP Web Interface Build Script" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Check if Node.js is installed
function Test-NodeJS {
    try {
        $nodeVersion = node --version 2>$null
        if ($nodeVersion) {
            Write-Host "✓ Node.js found: $nodeVersion" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "✗ Node.js not found" -ForegroundColor Red
        return $false
    }
    return $false
}

# Check if npm is installed
function Test-NPM {
    try {
        $npmVersion = npm --version 2>$null
        if ($npmVersion) {
            Write-Host "✓ npm found: v$npmVersion" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "✗ npm not found" -ForegroundColor Red
        return $false
    }
    return $false
}

# Install Node.js if not present
function Install-NodeJS {
    Write-Host "Installing Node.js..." -ForegroundColor Yellow
    
    $nodeVersion = "18.18.0"
    $nodeUrl = "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-x64.msi"
    $nodeInstaller = "$env:TEMP\node-installer.msi"
    
    try {
        Write-Host "Downloading Node.js v$nodeVersion..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $nodeUrl -OutFile $nodeInstaller -UseBasicParsing
        
        Write-Host "Installing Node.js..." -ForegroundColor Yellow
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $nodeInstaller, "/quiet", "/norestart" -Wait
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Clean up
        Remove-Item $nodeInstaller -Force -ErrorAction SilentlyContinue
        
        Write-Host "✓ Node.js installed successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ Failed to install Node.js: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main build process
function Build-WebInterface {
    Write-Host "\nBuilding OMAP Web Interface..." -ForegroundColor Cyan
    
    # Change to web directory
    $webDir = Split-Path -Parent $MyInvocation.ScriptName
    Set-Location $webDir
    
    Write-Host "Working directory: $webDir" -ForegroundColor Gray
    
    # Install dependencies
    Write-Host "\nInstalling dependencies..." -ForegroundColor Yellow
    try {
        npm install
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed"
        }
        Write-Host "✓ Dependencies installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to install dependencies: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    # Build the React app
    Write-Host "\nBuilding React application..." -ForegroundColor Yellow
    try {
        npm run build
        if ($LASTEXITCODE -ne 0) {
            throw "npm run build failed"
        }
        Write-Host "✓ React app built successfully" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to build React app: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    # Check if build directory exists
    if (Test-Path "./build") {
        Write-Host "✓ Build directory created: ./build" -ForegroundColor Green
        
        # List build contents
        $buildSize = (Get-ChildItem -Path "./build" -Recurse | Measure-Object -Property Length -Sum).Sum
        $buildSizeMB = [math]::Round($buildSize / 1MB, 2)
        Write-Host "  Build size: $buildSizeMB MB" -ForegroundColor Gray
        
        return $true
    } else {
        Write-Host "✗ Build directory not found" -ForegroundColor Red
        return $false
    }
}

# Build Go web server
function Build-GoServer {
    Write-Host "\nBuilding Go web server..." -ForegroundColor Cyan
    
    try {
        # Check if Go is available
        $goVersion = go version 2>$null
        if (-not $goVersion) {
            Write-Host "✗ Go not found. Please install Go first." -ForegroundColor Red
            return $false
        }
        
        Write-Host "✓ Go found: $goVersion" -ForegroundColor Green
        
        # Build the server
        Write-Host "Building web server executable..." -ForegroundColor Yellow
        go build -o omap-web.exe server.go
        
        if ($LASTEXITCODE -eq 0 -and (Test-Path "./omap-web.exe")) {
            Write-Host "✓ Web server built successfully: omap-web.exe" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Failed to build web server" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Error building Go server: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Test the build
function Test-Build {
    Write-Host "\nTesting build..." -ForegroundColor Cyan
    
    # Check required files
    $requiredFiles = @(
        "./build/index.html",
        "./build/static",
        "./omap-web.exe"
    )
    
    $allFilesExist = $true
    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            Write-Host "✓ Found: $file" -ForegroundColor Green
        } else {
            Write-Host "✗ Missing: $file" -ForegroundColor Red
            $allFilesExist = $false
        }
    }
    
    return $allFilesExist
}

# Main execution
try {
    # Check prerequisites
    if (-not (Test-NodeJS)) {
        if (-not (Install-NodeJS)) {
            Write-Host "\n✗ Cannot proceed without Node.js" -ForegroundColor Red
            exit 1
        }
        
        # Verify installation
        if (-not (Test-NodeJS)) {
            Write-Host "\n✗ Node.js installation verification failed" -ForegroundColor Red
            exit 1
        }
    }
    
    if (-not (Test-NPM)) {
        Write-Host "\n✗ npm is required but not found" -ForegroundColor Red
        exit 1
    }
    
    # Build web interface
    if (-not (Build-WebInterface)) {
        Write-Host "\n✗ Web interface build failed" -ForegroundColor Red
        exit 1
    }
    
    # Build Go server
    if (-not (Build-GoServer)) {
        Write-Host "\n✗ Go server build failed" -ForegroundColor Red
        exit 1
    }
    
    # Test build
    if (-not (Test-Build)) {
        Write-Host "\n✗ Build verification failed" -ForegroundColor Red
        exit 1
    }
    
    # Success message
    Write-Host "\n" -ForegroundColor Green
    Write-Host "🎉 OMAP Web Interface built successfully!" -ForegroundColor Green
    Write-Host "" -ForegroundColor Green
    Write-Host "To start the web server:" -ForegroundColor Cyan
    Write-Host "  .\omap-web.exe [port] [static-dir]" -ForegroundColor White
    Write-Host "" -ForegroundColor Green
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\omap-web.exe                    # Start on port 8080" -ForegroundColor White
    Write-Host "  .\omap-web.exe 3000               # Start on port 3000" -ForegroundColor White
    Write-Host "  .\omap-web.exe 8080 ./build       # Custom static directory" -ForegroundColor White
    Write-Host "" -ForegroundColor Green
    Write-Host "Then open http://localhost:8080 in your browser" -ForegroundColor Cyan
    
} catch {
    Write-Host "\n✗ Build failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}