# Define the Decrypt-ValidationLogic function
function Decrypt-ValidationLogic {
    param (
        [string]$encryptedValidation,
        [string]$key
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $keyBytes = [Convert]::FromBase64String($key)
    $aes.Key = $keyBytes

    $fullBytes = [Convert]::FromBase64String($encryptedValidation)
    $aes.IV = $fullBytes[0..15]
    $cipherText = $fullBytes[16..$fullBytes.Length]

    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)

    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

Clear-Host

# Display ASCII art and set window title
$asciiArtUrl = "https://raw.githubusercontent.com/Reapiin/art/main/art.ps1"
$asciiArtScript = Invoke-RestMethod -Uri $asciiArtUrl
Invoke-Expression $asciiArtScript

$encodedTitle = "Q3JlYXRlZCBieSBSZWFwaWluIG9uIGRpc2NvcmQu"
$titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTitle))
$Host.UI.RawUI.WindowTitle = $titleText

# Check Secure Boot status
function Check-SecureBoot {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBootState = Confirm-SecureBootUEFI
            if ($secureBootState) {
                Write-Host "`n[-] Secure Boot is ON." -ForegroundColor Green
            } else {
                Write-Host "`n[-] Secure Boot is OFF." -ForegroundColor Red
            }
        } else {
            Write-Host "`n[-] Secure Boot not available on this system." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "`n[-] Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    }
}
Check-SecureBoot

# Get OneDrive path from registry or environment
function Get-OneDrivePath {
    try {
        $oneDrivePath = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder").UserFolder
        if (-not $oneDrivePath) {
            Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
            $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")
            if (Test-Path $envOneDrive) {
                $oneDrivePath = $envOneDrive
                Write-Host "[-] OneDrive path detected using environment variable: $oneDrivePath" -ForegroundColor Green
            } else {
                Write-Error "Unable to find OneDrive path automatically."
            }
        }
        return $oneDrivePath
    } catch {
        Write-Error "Unable to find OneDrive path: $_"
        return $null
    }
}

# Format output to clean up certain strings
function Format-Output {
    param($name, $value)
    $output = "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
    if ($output -notmatch "Steam|Origin|EAPlay|FileSyncConfig.exe|OutlookForWindows") {
        return $output
    }
}

# Log folder names and prompt user for action on Stats.cc
function Log-FolderNames {
    $userName = $env:UserName
    $oneDrivePath = Get-OneDrivePath
    $potentialPaths = @("C:\Users\$userName\Documents\My Games\Rainbow Six - Siege", "$oneDrivePath\Documents\My Games\Rainbow Six - Siege")
    $allUserNames = @()

    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            $dirNames = Get-ChildItem -Path $path -Directory | ForEach-Object { $_.Name }
            $allUserNames += $dirNames
        }
    }

    $uniqueUserNames = $allUserNames | Select-Object -Unique

    if ($uniqueUserNames.Count -eq 0) {
        Write-Host "`nSkipping Stats.cc Search" -ForegroundColor Yellow
    } else {
        Write-Host "`nR6 Usernames Detected. Summon Stats.cc? | (Y/N)"
        $userResponse = Read-Host

        if ($userResponse -eq "Y") {
            foreach ($name in $uniqueUserNames) {
                $url = "https://stats.cc/siege/$name"
                Write-Host " [-] Opening stats for $name on Stats.cc ..." -ForegroundColor DarkMagenta
                Start-Process $url
                Start-Sleep -Seconds 0.5
            }
        } else {
            Write-Host "Stats.cc Search Skipped" -ForegroundColor Yellow
        }
    }
}

# Find suspicious file names (e.g., loaders)
function Find-SusFiles {
    Write-Host " [-] Finding suspicious files names..." -ForegroundColor DarkMagenta
    $susFiles = @()

    foreach ($file in $global:logEntries) {
        if ($file -match "loader.*\.exe") { $susFiles += $file }
    }

    if ($susFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------`nSus Files(Files with loader in their name):`n"
        $global:logEntries += $susFiles | Sort-Object
    }
}

# Find .zip and .rar files
function Find-ZipRarFiles {
    Write-Host " [-] Finding .zip and .rar files. Please wait..." -ForegroundColor DarkMagenta
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Include *.zip, *.rar -File
            foreach ($file in $files) {
                if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft") {
                    $uniquePaths[$file.FullName] = $true
                    $zipRarFiles += $file
                }
            }
        }
    }

    return $zipRarFiles
}

# Log BAM State User Settings
function List-BAMStateUserSettings {
    Write-Host " `n [-] Fetching UserSettings Entries " -ForegroundColor DarkMagenta
    $loggedPaths = @{ }

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            $global:logEntries += "`n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                    $global:logEntries += "`n" + (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
    } else {
        Write-Host " [-] No relevant user settings found." -ForegroundColor Red
    }
}

# Log Windows install date
function Log-WindowsInstallDate {
    Write-Host " [-] Logging Windows install date..." -ForegroundColor DarkMagenta
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.ConvertToDateTime($os.InstallDate)
    $global:logEntries += "`n==============="
    $global:logEntries += "`nWindows Installation Date: $installDate"
}

# Check for .tlscan folders in recent docs
function Check-RecentDocsForTlscan {
    Write-Host " [-] Checking for .tlscan folders..." -ForegroundColor DarkMagenta
    $recentDocsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $tlscanFound = $false
    if (Test-Path $recentDocsPath) {
        $recentDocs = Get-ChildItem -Path $recentDocsPath
        foreach ($item in $recentDocs) {
            if ($item.PSChildName -match "\.tlscan") {
                $tlscanFound = $
