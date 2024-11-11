# Download and execute the script from GitHub
$scriptUrl = "https://raw.githubusercontent.com/suprsor/Pc-Checker-Main/refs/heads/main/SuprsorsPcCheck.ps1"

# Clear the screen and set title
Clear-Host
$host.ui.RawUI.WindowTitle = "PcCheck by Suprsor"

# ASCII Art (Rose)
$art = @"
            ⠀⣤⢔⣒⠂⣀⣀⣤⣄⣀⠀⠀ 
⠀⠀⠀⠀  ⠀⠀⠀⣴⣿⠋⢠⣟⡼⣷⠼⣆⣼⢇⣿⣄⠱⣄
⠀⠀⠀  ⠀⠀⠀⠀⠹⣿⡀⣆⠙⠢⠐⠉⠉⣴⣾⣽⢟⡰⠃
⠀⠀⠀⠀⠀  ⠀⠀⠀⠈⢿⣿⣦⠀⠤⢴⣿⠿⢋⣴⡏⠀⠀
⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⢸⡙⠻⣿⣶⣦⣭⣉⠁⣿⠀⠀⠀
⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⠀⣷⠀⠈⠉⠉⠉⠉⠇⡟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀  ⢀⠀⠀⣘⣦⣀⠀⠀⣀⡴⠊⠀⠀⠀⠀
⠀⠀⠀  ⠀⠀⠀⠀⠈⠙⠛⠛⢻⣿⣿⣿⣿⠻⣧⡀⠀⠀⠀
⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠈⠫⣿⠉⠻⣇⠘⠓⠂⠀⠀
⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀
  ⢶⣾⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀ ⠀⠹⣿⣿⣿⣿⣿⣿⣿⣧⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀
  ⠀⠀⠈⠙⠻⢿⣿⣿⠿⠛⣄⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⣿                  
"@
Write-Host $art

# Hide the output of scanning steps and show progress bar
$progressBar = 0
$progressBarMax = 100

# Define progress function
function Show-ProgressBar {
    param (
        [int]$currentStep,
        [int]$maxSteps
    )
    $percentage = [math]::Round(($currentStep / $maxSteps) * 100)
    $progressBarText = "$percentage% Complete"
    $progressBarString = "=" * $percentage
    $progressBarString = $progressBarString.PadRight(100, " ")
    Write-Host "$progressBarString $progressBarText"
}

# Check for OneDrive Path
$oneDrivePath = $null
$regKey = "HKCU:\Software\Microsoft\OneDrive"
if (Test-Path $regKey) {
    $oneDrivePath = (Get-ItemProperty -Path $regKey -Name "UserFolder").UserFolder
}

if (-not $oneDrivePath) {
    $oneDrivePath = [System.Environment]::GetEnvironmentVariable("OneDrive", [System.EnvironmentVariableTarget]::User)
}

if (-not $oneDrivePath) {
    Write-Host "Error: OneDrive path not found. Please check your OneDrive installation."
    exit
} 

# Scan Files
$exeFiles = Get-ChildItem -Path $oneDrivePath -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue
$rarFiles = Get-ChildItem -Path $oneDrivePath -Recurse -Filter "*.rar" -ErrorAction SilentlyContinue

# Update progress bar (let's say we're done after scanning)
$progressBar = 20
Show-ProgressBar -currentStep $progressBar -maxSteps $progressBarMax

# Log the detected files
$logPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "PcCheckLogs.txt")
$logMessage = "Detected EXE Files:`n" + ($exeFiles | ForEach-Object { $_.FullName }) + "`n"
$logMessage += "Detected RAR Files:`n" + ($rarFiles | ForEach-Object { $_.FullName })

Set-Content -Path $logPath -Value $logMessage

# Update progress bar after logging
$progressBar = 60
Show-ProgressBar -currentStep $progressBar -maxSteps $progressBarMax

# Scan is complete, so finalize the progress
$progressBar = 100
Show-ProgressBar -currentStep $progressBar -maxSteps $progressBarMax

Write-Host "`nScanning complete! Logs have been saved to: $logPath"
