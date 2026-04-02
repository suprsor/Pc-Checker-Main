# Clear the PowerShell window and set title
Clear-Host
$host.UI.RawUI.WindowTitle = "Created By: Suprsors on Discord"

# Output file
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$outputFile = Join-Path $desktopPath "PcCheckLogs.txt"

# Reset log
if (Test-Path $outputFile) { Clear-Content $outputFile }

# -------------------------
# OneDrive Path Detection
# -------------------------
function Get-OneDrivePath {
    try {
        $path = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder").UserFolder
        if (-not $path) {
            $alt = Join-Path $env:UserProfile "OneDrive"
            if (Test-Path $alt) { $path = $alt }
        }
        return $path
    } catch {
        return $null
    }
}

# -------------------------
# Prefetch Scanner
# -------------------------
function Log-PrefetchFiles {
    Write-Host "Scanning Prefetch..." -ForegroundColor Cyan
    $prefetchPath = "C:\Windows\Prefetch"

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "Prefetch Data:"

    if (Test-Path $prefetchPath) {
        Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name -replace "-.*", ""   # Clean app name
            $lastRun = $_.LastWriteTime
            Add-Content $outputFile "$name : $lastRun"
        }
    } else {
        Add-Content $outputFile "Prefetch not accessible"
    }
}

# -------------------------
# File Scanner (Expanded)
# -------------------------
function Find-Files {
    Write-Host "Scanning for files..." -ForegroundColor Yellow

    $extensions = "*.exe","*.rar","*.tlscan","*.cfg"
    $searchPaths = @()

    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $searchPaths += $_.Root
    }

    $oneDrive = Get-OneDrivePath
    if ($oneDrive) { $searchPaths += $oneDrive }

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "Detected Files:"

    foreach ($path in $searchPaths) {
        foreach ($ext in $extensions) {
            Get-ChildItem -Path $path -Recurse -Filter $ext -ErrorAction SilentlyContinue | ForEach-Object {
                Add-Content $outputFile $_.FullName
            }
        }
    }
}

# -------------------------
# Suspicious Name Scanner
# -------------------------
function Find-SusFiles {
    Write-Host "Checking suspicious names..." -ForegroundColor Red

    if (Test-Path $outputFile) {
        $content = Get-Content $outputFile
        $sus = $content | Where-Object { $_ -match "loader.*\.exe" }

        if ($sus) {
            Add-Content $outputFile "`n-----------------"
            Add-Content $outputFile "Suspicious Files:"
            $sus | ForEach-Object { Add-Content $outputFile $_ }
        }
    }
}

# -------------------------
# Registry Execution Logs
# -------------------------
function Log-RegistryExecution {
    Write-Host "Logging registry traces..." -ForegroundColor Magenta

    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    )

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "Registry Execution:"

    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ItemProperty $path | ForEach-Object {
                $_.PSObject.Properties | ForEach-Object {
                    if ($_.Name -match "\.(exe|rar|tlscan|cfg)") {
                        Add-Content $outputFile $_.Name
                    }
                }
            }
        }
    }
}

# -------------------------
# Browser Detection
# -------------------------
function Log-Browsers {
    $path = "HKLM:\SOFTWARE\Clients\StartMenuInternet"

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "Browsers:"

    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            Add-Content $outputFile $_.Name
        }
    }
}

# -------------------------
# Windows Install Date
# -------------------------
function Log-WindowsInstall {
    $os = Get-WmiObject Win32_OperatingSystem
    $date = $os.ConvertToDateTime($os.InstallDate)

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "Windows Install Date: $date"
}

# -------------------------
# R6 Username Grabber
# -------------------------
function Log-R6Users {
    $user = $env:UserName
    $oneDrive = Get-OneDrivePath

    $paths = @(
        "C:\Users\$user\Documents\My Games\Rainbow Six - Siege",
        "$oneDrive\Documents\My Games\Rainbow Six - Siege"
    )

    Add-Content $outputFile "`n-----------------"
    Add-Content $outputFile "R6 Usernames:"

    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p -Directory | ForEach-Object {
                Add-Content $outputFile $_.Name
                Start-Process "https://stats.cc/siege/$($_.Name)"
                Start-Sleep 0.5
            }
        }
    }
}

# -------------------------
# RUN EVERYTHING
# -------------------------
Log-RegistryExecution
Log-WindowsInstall
Log-Browsers
Log-R6Users
Log-PrefetchFiles
Find-Files
Find-SusFiles

# Copy log to clipboard
if (Test-Path $outputFile) {
    Set-Clipboard -Path $outputFile
    Write-Host "Log copied to clipboard." -ForegroundColor Cyan
}

# Final message
Write-Host "`n╭────────────────────────────╮" -ForegroundColor Red
Write-Host "│       SCAN COMPLETE        │" -ForegroundColor Red
Write-Host "╰────────────────────────────╯" -ForegroundColor Red

Write-Host "`nDiscord @suprsors" -ForegroundColor Magenta
