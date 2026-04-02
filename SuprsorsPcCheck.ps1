# Clear the PowerShell window and set title
Clear-Host
$host.UI.RawUI.WindowTitle = "Created By: Suprsors on Discord"

# Output file
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$outputFile = Join-Path $desktopPath "PcCheckLogs.txt"

# Reset log
if (Test-Path $outputFile) { Clear-Content $outputFile }

# Globals
$global:Logged = @{}
$global:Findings = @()

# -------------------------
# Logging Helper
# -------------------------
function Write-Log {
    param($text)
    Add-Content $outputFile $text
}

# -------------------------
# Risk Helper
# -------------------------
function Add-Finding {
    param($path, $reason)

    if (-not $global:Findings.Contains("$path|$reason")) {
        $global:Findings += "$path -> $reason"
    }
}

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
# Signature Check (NEW)
# -------------------------
function Check-Signature {
    param($file)

    try {
        $sig = Get-AuthenticodeSignature $file
        if ($sig.Status -ne "Valid") {
            Add-Finding $file "Unsigned/Invalid Signature"
        }
    } catch {}
}

# -------------------------
# Prefetch Scanner
# -------------------------
function Log-PrefetchFiles {
    Write-Host "Scanning Prefetch..." -ForegroundColor Cyan
    $prefetchPath = "C:\Windows\Prefetch"

    Write-Log "`n-----------------"
    Write-Log "Prefetch Data:"

    if (Test-Path $prefetchPath) {
        Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name -replace "-.*", ""
            $lastRun = $_.LastWriteTime

            Write-Log "$name : $lastRun"

            if ($lastRun -gt (Get-Date).AddDays(-2)) {
                Add-Finding $name "Recently Executed (Prefetch)"
            }
        }
    } else {
        Write-Log "Prefetch not accessible"
    }
}

# -------------------------
# File Scanner (Optimized)
# -------------------------
function Find-Files {
    Write-Host "Scanning for files..." -ForegroundColor Yellow

    $extensions = @("*.exe","*.rar","*.tlscan","*.cfg")
    $searchPaths = @()

    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $searchPaths += $_.Root
    }

    $oneDrive = Get-OneDrivePath
    if ($oneDrive) { $searchPaths += $oneDrive }

    Write-Log "`n-----------------"
    Write-Log "Detected Files:"

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Include $extensions -ErrorAction SilentlyContinue | ForEach-Object {

                if (-not $global:Logged.ContainsKey($_.FullName)) {
                    Write-Log $_.FullName
                    $global:Logged[$_.FullName] = $true

                    # Checks
                    Check-Signature $_.FullName

                    if ($_.LastWriteTime -gt (Get-Date).AddDays(-2)) {
                        Add-Finding $_.FullName "Recently Modified"
                    }

                    if ($_.Name -match "loader|inject|hack|cheat") {
                        Add-Finding $_.FullName "Suspicious Name"
                    }
                }
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
            Write-Log "`n-----------------"
            Write-Log "Suspicious Files:"
            $sus | ForEach-Object { Write-Log $_ }
        }
    }
}

# -------------------------
# Registry Execution Logs (IMPROVED + MUI)
# -------------------------
function Log-RegistryExecution {
    Write-Host "Logging registry traces..." -ForegroundColor Magenta

    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        "HKCR:\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    )

    Write-Log "`n-----------------"
    Write-Log "Registry Execution:"

    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ItemProperty $path | ForEach-Object {
                $_.PSObject.Properties | ForEach-Object {
                    if ($_.Name -match "\.(exe|rar|tlscan|cfg)") {

                        if (-not $global:Logged.ContainsKey($_.Name)) {
                            Write-Log $_.Name
                            $global:Logged[$_.Name] = $true
                            Add-Finding $_.Name "Registry Execution Trace"
                        }
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

    Write-Log "`n-----------------"
    Write-Log "Browsers:"

    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            Write-Log $_.Name
        }
    }
}

# -------------------------
# Windows Install Date
# -------------------------
function Log-WindowsInstall {
    $os = Get-WmiObject Win32_OperatingSystem
    $date = $os.ConvertToDateTime($os.InstallDate)

    Write-Log "`n-----------------"
    Write-Log "Windows Install Date: $date"
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

    Write-Log "`n-----------------"
    Write-Log "R6 Usernames:"

    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p -Directory | ForEach-Object {
                Write-Log $_.Name
                Start-Process "https://stats.cc/siege/$($_.Name)"
                Start-Sleep 0.5
            }
        }
    }
}

# -------------------------
# Final Risk Summary (NEW)
# -------------------------
function Generate-Summary {
    Write-Log "`n===================="
    Write-Log "Findings Summary"
    Write-Log "===================="

    foreach ($f in $global:Findings) {
        Write-Log $f
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
Generate-Summary

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
