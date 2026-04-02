# -------------------------
# UTF-8 FIX (MUST BE FIRST)
# -------------------------
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

# Clear the PowerShell window and set title
Clear-Host
$host.UI.RawUI.WindowTitle = "Fiori's Pc-Check tool"

# -------------------------
# ASCII BANNER
# -------------------------
$banner = @"
Made By @suprsor/Fiori on Discord. Full code is published on my Github. 
"@

$banner.Split("`n") | ForEach-Object {
    Write-Host $_ -ForegroundColor Cyan
}

Write-Host "`nStarting...`n" -ForegroundColor Magenta

# -------------------------
# OUTPUT SETUP
# -------------------------
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$outputFile = Join-Path $desktopPath "PcCheckLogs.txt"
if (Test-Path $outputFile) { Clear-Content $outputFile }

# Globals
$global:Logged = @{}
$global:Findings = @()

# -------------------------
# LOGGING
# -------------------------
function Write-Log { param($text) Add-Content $outputFile $text }
function Add-Finding { param($path,$reason) $key="$path|$reason"; if (-not $global:Findings.Contains($key)) { $global:Findings += "$path -> $reason" } }

# -------------------------
# ONEDRIVE
# -------------------------
function Get-OneDrivePath {
    try {
        $path = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder").UserFolder
        if (-not $path) {
            $alt = Join-Path $env:UserProfile "OneDrive"
            if (Test-Path $alt) { $path = $alt }
        }
        return $path
    } catch { return $null }
}

# -------------------------
# SIGNATURE CHECK
# -------------------------
function Check-Signature {
    param($item)
    try {
        if (-not $item.PSIsContainer) {
            $sig = Get-AuthenticodeSignature $item.FullName
            if ($sig.Status -ne "Valid") { Add-Finding $item.FullName "Unsigned/Invalid Signature" }
        }
    } catch {}
}

# -------------------------
# PREFETCH
# -------------------------
function Log-PrefetchFiles {
    Write-Host "Scanning Prefetch..." -ForegroundColor Cyan
    $prefetchPath = "C:\Windows\Prefetch"
    Write-Log "`n-----------------"
    Write-Log "Prefetch Data:"
    if (Test-Path $prefetchPath) {
        Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name -replace "-.*",""
            $lastRun = $_.LastWriteTime
            Write-Log "$name : $lastRun"
            if ($lastRun -gt (Get-Date).AddDays(-2)) { Add-Finding $name "Recently Executed (Prefetch)" }
        }
    } else { Write-Log "Prefetch not accessible" }
}

# -------------------------
# FILE SCAN
# -------------------------
function Find-Files {
    Write-Host "Scanning for files..." -ForegroundColor Yellow
    $extensions = @(".exe",".rar",".tlscan",".cfg")
    $searchPaths = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:APPDATA","$env:LOCALAPPDATA")
    $oneDrive = Get-OneDrivePath
    if ($oneDrive) { $searchPaths += $oneDrive }
    Write-Log "`n-----------------"
    Write-Log "Detected Files:"
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                if ($extensions -contains $_.Extension.ToLower()) {
                    if (-not $global:Logged.ContainsKey($_.FullName)) {
                        Write-Log $_.FullName
                        $global:Logged[$_.FullName]= $true
                        Check-Signature $_
                        if ($_.LastWriteTime -gt (Get-Date).AddDays(-2)) { Add-Finding $_.FullName "Recently Modified" }
                        if ($_.Name -match "loader|inject|hack|cheat") { Add-Finding $_.FullName "Suspicious Name" }
                    }
                }
            }
        }
    }
}

# -------------------------
# SUSPICIOUS NAME SCAN
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
# REGISTRY (WITH MUI)
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
                            $global:Logged[$_.Name]= $true
                            Add-Finding $_.Name "Registry Execution Trace"
                        }
                    }
                }
            }
        }
    }
}

# -------------------------
# BROWSERS
# -------------------------
function Log-Browsers {
    $path = "HKLM:\SOFTWARE\Clients\StartMenuInternet"
    Write-Log "`n-----------------"
    Write-Log "Browsers:"
    if (Test-Path $path) { Get-ChildItem $path | ForEach-Object { Write-Log $_.Name } }
}

# -------------------------
# WINDOWS INFO (WITH SECURE BOOT & FULL VERSION FIXED)
# -------------------------
function Log-WindowsInstall {
    Write-Host "Logging Windows info..." -ForegroundColor Cyan

# Simple Install Date Grab
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$installDateEpoch = (Get-ItemProperty $regPath).InstallDate
$installDate = Get-Date ([System.DateTimeOffset]::FromUnixTimeSeconds($installDateEpoch).DateTime) 
Write-Host "Windows Install Date: $installDate"
    # OS Info
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $build = [int]$os.BuildNumber
    $versionNumber = $os.Version

    # Convert InstallDate safely
    try {
        if ($os.InstallDate -and $os.InstallDate -ne "") {
            $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
        } else {
            $installDate = "Unknown"
        }
    } catch {
        $installDate = "Unknown"
    }

    # Determine H2/H1 release info
    $release = ""
    if ($caption -match "Windows 10") {
        switch ($build) {
            {$_ -ge 19044} { $release = "22H2"; break }
            {$_ -ge 19043} { $release = "21H2"; break }
            {$_ -ge 19042} { $release = "20H2"; break }
            {$_ -ge 19041} { $release = "2004/20H1"; break }
            default { $release = "Older" }
        }
    } elseif ($caption -match "Windows 11") {
        switch ($build) {
            {$_ -ge 22621} { $release = "24H2"; break }
            {$_ -ge 22000} { $release = "21H2"; break }
            default { $release = "Older" }
        }
    }

    $fullVersion = "$caption $release (Build $build, Version $versionNumber)"

    # Secure Boot Status
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        if (Confirm-SecureBootUEFI) { $secureBoot = "Enabled" } else { $secureBoot = "Disabled" }
    } else { $secureBoot = "Unknown" }

    # Windows Defender / AV Status
    try {
        $av = Get-MpComputerStatus
        $firewall = if ($av.FirewallEnabled) {"Enabled"} else {"Disabled"}
        $realTime = if ($av.RealTimeProtectionEnabled) {"Enabled"} else {"Disabled"}
    } catch {
        $firewall = "Unknown"
        $realTime = "Unknown"
    }

    # Log everything
    Write-Log "`n-----------------"
    Write-Log "Windows Install Date: $installDate"
    Write-Log "Windows Version: $fullVersion"
    Write-Log "Secure Boot Status: $secureBoot"
    Write-Log "Firewall Status: $firewall"
    Write-Log "Real-Time Protection: $realTime"
}
# -------------------------
# PCIE & USB DEVICES
# -------------------------
function Log-PCIEandUSB {
    Write-Host "Logging PCIe & USB devices..." -ForegroundColor Cyan
    Write-Log "`n-----------------"
    Write-Log "PCIE & USB Devices:"

    # Get all PnP devices
    $devices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match "PCI|USB" }

    foreach ($dev in $devices) {
        $name = $dev.Name
        $status = if ($dev.Status -eq "OK") {"Plugged In"} else {"Unplugged/Inactive"}

        # Extract Vendor ID / Product ID if available
        if ($dev.PNPDeviceID -match "VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})") {
            $vid = $matches[1]
            $pid = $matches[2]
        } else {
            $vid = "Unknown"
            $pid = "Unknown"
        }

        Write-Log "$name | $status | VID:$vid PID:$pid | PNPDeviceID:$($dev.PNPDeviceID)"
    }
}
# -------------------------
# DEVICE MANAGER LOG (FIXED VID/PID)
# -------------------------
function Log-Devices {
    Write-Host "Logging Device Manager info..." -ForegroundColor Cyan
    $categories = @("Display","Ports","HIDClass","Net","USB","Mouse")
    Write-Log "`n-----------------"
    Write-Log "Device Manager Info:"

    foreach ($cat in $categories) {
        Write-Log "`n$cat Devices:"
        $devs = Get-PnpDevice -Class $cat -ErrorAction SilentlyContinue

        foreach ($dev in $devs) {
            # Default values
            $deviceVID = "Unknown"
            $devicePID = "Unknown"
            $status = if ($dev.Status -eq "OK") {"Plugged In"} else {"Unplugged/Inactive"}

            # Try to extract VID/PID from InstanceId
            if ($dev.InstanceId -match "VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})") {
                $deviceVID = $matches[1]
                $devicePID = $matches[2]
            }

            # Only log if we have at least one valid VID or PID
            if ($deviceVID -ne "Unknown" -or $devicePID -ne "Unknown") {
                Write-Log "$($dev.Name) | $status | VID:$deviceVID PID:$devicePID"
            }
        }
    }
}
# -------------------------
# R6 USERS
# -------------------------
function Log-R6Users {
    $user = $env:UserName
    $oneDrive = Get-OneDrivePath
    $paths = @("C:\Users\$user\Documents\My Games\Rainbow Six - Siege","$oneDrive\Documents\My Games\Rainbow Six - Siege")
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
# LOGITECH GHUB SCRIPTS
# -------------------------
function Log-GHubScripts {
    $user = $env:UserName
    $path = "C:\Users\$user\AppData\Local\LGHUB\scripts"
    if (Test-Path $path) {
        Write-Log "`n-----------------"
        Write-Log "Logitech GHUB Scripts:"
        Get-ChildItem -Path $path -Directory | ForEach-Object { Write-Log $_.Name }
    }
}

# -------------------------
# SUMMARY
# -------------------------
function Generate-Summary {
    Write-Log "`n===================="
    Write-Log "Findings Summary"
    Write-Log "===================="
    foreach ($f in $global:Findings) { Write-Log $f }
}

# -------------------------
# RUN
# -------------------------
Log-RegistryExecution
Log-WindowsInstall
Log-Browsers
Log-R6Users
Log-PrefetchFiles
Find-Files
Find-SusFiles
Log-Devices
Log-GHubScripts
Generate-Summary

# Copy log to clipboard
if (Test-Path $outputFile) {
    Set-Clipboard -Path $outputFile
    Write-Host "Log copied to clipboard." -ForegroundColor Cyan
}

Write-Host "`n=============================="
Write-Host "       SCAN COMPLETE          "
Write-Host "=============================="
Write-Host "Discord @suprsors"
