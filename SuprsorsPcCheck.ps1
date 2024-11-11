# Global variable initialization
$global:logEntries = @()

# Helper function for logging
function Log-Message {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $logEntry = "$([DateTime]::Now) - [$level] - $message"
    $global:logEntries += $logEntry
    Write-Host $logEntry
}

# Function to decrypt encrypted validation data
function Decrypt-ValidationLogic {
    param (
        [string]$encryptedValidation,
        [string]$encryptionKey
    )

    try {
        $fullBytes = [Convert]::FromBase64String($encryptedValidation)
        if ($fullBytes.Length -gt 16) {
            $aes = [System.Security.Cryptography.AesManaged]::new()
            $aes.Key = [Convert]::FromBase64String($encryptionKey)
            $aes.IV = $fullBytes[0..15]
            $cipherText = $fullBytes[16..$fullBytes.Length]

            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
            $decryptedData = [Text.Encoding]::UTF8.GetString($decryptedBytes)

            Log-Message "Decryption successful."
            return $decryptedData
        } else {
            Log-Message "Invalid encrypted validation data." "ERROR"
            return $null
        }
    } catch {
        Log-Message "Decryption failed: $_" "ERROR"
        return $null
    }
}

# Function to check if Secure Boot is enabled
function Check-SecureBoot {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction Stop) {
            $secureBootState = Confirm-SecureBootUEFI
            if ($secureBootState) {
                Log-Message "Secure Boot is ON."
            } else {
                Log-Message "Secure Boot is OFF."
            }
        } else {
            Log-Message "Secure Boot not available on this system." "WARNING"
        }
    } catch {
        Log-Message "Error checking Secure Boot: $_" "ERROR"
    }
}

# Function to get the OneDrive path
function Get-OneDrivePath {
    $oneDrivePath = [System.IO.Path]::Combine($env:OneDrive, "Documents\My Games\Rainbow Six - Siege")
    if (Test-Path $oneDrivePath) {
        Log-Message "Found OneDrive path: $oneDrivePath."
        return $oneDrivePath
    } else {
        Log-Message "OneDrive path not found." "ERROR"
        return $null
    }
}

# Function to scan for suspicious files
function Find-SusFiles {
    param (
        [string]$path
    )

    if (-not (Test-Path $path)) {
        Log-Message "Path not found: $path" "ERROR"
        return @()
    }

    $susFiles = Get-ChildItem -Path $path -Recurse | Where-Object { $_.Name -like "*loader*" }
    if ($susFiles.Count -eq 0) {
        Log-Message "No suspicious files found in $path." "INFO"
    } else {
        Log-Message "Found suspicious files: $($susFiles.Count)." "WARNING"
    }
    return $susFiles
}

# Main function
function Main {
    Log-Message "Starting the script..."

    # Check Secure Boot
    Check-SecureBoot

    # Decrypt validation logic
    $encryptedValidation = "YOUR_ENCRYPTED_VALIDATION_STRING"
    $encryptionKey = "YOUR_ENCRYPTION_KEY"
    $decryptedData = Decrypt-ValidationLogic -encryptedValidation $encryptedValidation -encryptionKey $encryptionKey
    if ($decryptedData) {
        Log-Message "Decrypted data: $decryptedData."
    }

    # Get OneDrive path and scan for suspicious files
    $oneDrivePath = Get-OneDrivePath
    if ($oneDrivePath) {
        $susFiles = Find-SusFiles -path $oneDrivePath
        foreach ($file in $susFiles) {
            Log-Message "Suspicious file found: $($file.FullName)." "ALERT"
        }
    }

    Log-Message "Script completed."
}

# Run the main function
Main
