<#
.SYNOPSIS
    Audits 1Password vault for weak or placeholder passwords.

.DESCRIPTION
    Prompts for action: open matching URLs, export results to Excel, both, or just output to the terminal.
    Scans each login item in the specified vault, highlights entries that match your patterns
    (e.g., 'CHANGEME0', 'CHANGEME1'), and shows two progress bars:
        - One for overall scan progress
        - One for the next batch of URLs waiting to open
    If opening URLs, it launches them in groups of 10 and pauses for you to press Enter before continuing.
    If your 1Password session times out mid-scan, the script will pause, prompt you to sign in again,
    clear the current URL batch, and then resume safely.

.EXAMPLE
    PS C:\> .\op-bad-password-audit.ps1
    Select “Both” when prompted to open URLs in the browser (10 at a time) and save an Excel report
    to your Desktop. The script scans, displays progress, handles re-authentication, and performs actions.

.INPUTS
    None via pipeline; prompts for user input during execution.

.OUTPUTS
    - Opens browser tabs in batches (if selected)
    - Generates an Excel file on the Desktop with matches (if selected)
    - Displays matching entries in the console

.NOTES
    - Requires PowerShell Core (or 5.1+) and the 1Password CLI installed and signed in.
    - ImportExcel module must be installed for Excel export.
    - Change `$vaultName` or pattern matching as needed to suit your environment.
    - Tested on Windows and macOS with PowerShell Core.
#>

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- PREP -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# Check if op session is active
try {
    $test = op vault list --format json | ConvertFrom-Json
}
catch {
    Write-Warning "1Password session appears to have timed out or failed."
    Write-Host "Signing in..." -ForegroundColor Yellow
    op signin
}

# Set default file output - Platform OS-independent
$output = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "BadPasswords.xlsx")
$vaultName = "XXXXX"

# Delete file if it already exists
if (Test-Path $output) {
    Remove-Item $output -ErrorAction SilentlyContinue
}

# Prompt user for action
Write-Host "`r`nWhat would you like to do?" -ForegroundColor Cyan
Write-Host "
    1. Open URLs
    2. Export to Excel
    3. Both 1 and 2
    4. Output to Terminal
    5. Exit" -ForegroundColor White

$choice = Read-Host "`nEnter your choice"

switch ($choice) {
    '1' { $doOpenUrls = $true; $doExportExcel = $false }
    '2' { $doOpenUrls = $false; $doExportExcel = $true }
    '3' { $doOpenUrls = $true; $doExportExcel = $true }
    '4' { $doOpenUrls = $false; $doExportExcel = $false }
    '5' { Write-Host "Operation cancelled." -ForegroundColor Yellow; return }
    default { Write-Host "Invalid choice. Exiting..." -ForegroundColor Red; return }
}

# Get login items
$items = op item list --vault $vaultName --categories Login --format json | ConvertFrom-Json #this makes it an object to retrieve info from
$total = $items.Count
$counter = 0

# Trackers
$results = @()
$urlbatch = @()
$batchsize = 10
$validUrlCount = 0

# Timer Start
#$scanStart = Get-Date

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- SCAN -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Write-Host "`nSearching...`n" -ForegroundColor Cyan

foreach ($item in $items) {
    $counter++
    $percentComplete = [math]::Round(($counter / $total) * 100)
    # ------ Percentage Complete
    Write-Progress -Id 1 -Activity "Scanning items..." -Status "$percentComplete% complete" -PercentComplete $percentComplete
    # ------ Items / Items
    #Write-Progress -Activity "Scanning items..." -Status "$counter of $total" -PercentComplete $percentComplete

    $id = $item.id

    # Get username + password
    $fields = op item get $id --vault $vaultName --fields label=username,label=password --format json | ConvertFrom-Json
    $username = ($fields.Where({ $_.label -eq "username" }, 'First')).value
    $password = ($fields.Where({ $_.label -eq "password" }, 'First')).value

    # Perform checks
    if ($password -match '(?i)CHANGEME0' -or $password -match '(?i)CHANGEME1') {
        # Get full item only if password matches
        $fullItem = op item get $id --vault $vaultName --format json | ConvertFrom-Json
        if (-not $fullItem -or -not $fullItem.fields) {
            Write-Warning "Failed to retrieve full item for ID $id. Skipping..."
            continue
        }

    $title = $fullItem.title

    Write-Color "Match found:", " $($title)" -Color White, Green
        Write-Host "Username: $username"
        Write-Host "--------------------------"

        if ($doExportExcel) {
            $results += [PSCustomObject]@{
                Title = $title
                Username = $username
                Password = $password
            }
        }

        if ($doOpenUrls) {
            $url = $fullItem.urls | Select-Object -ExpandProperty href -First 1

            if ($url -and $url -match '^https?://') {
                $urlBatch += $url
                $validUrlCount++
                
                # Update second progress bar - URLs Found
                Write-Progress -Id 2 -Activity "URLs Found" `
                    -Status "$($urlBatch.Count) of $batchSize URLs" `
                    -PercentComplete ([math]::Round(($urlBatch.Count / $batchSize) * 100))

                if ($validUrlCount -eq $batchSize) {
                    foreach ($u in $urlBatch) {
                        Start-Process $u
                    }
                    
                    # Pause after 10 URLs caught and opened
                    Write-Host "`nOpened $batchSize sites. Press Enter to continue scanning..." -ForegroundColor Yellow
                    Read-Host

                    # Re-check if op is still authenticated
                    try {
                        $test = op vault list --format json | ConvertFrom-Json
                    }
                    catch {
                        Write-Warning "`n1Password session timed out. You must sign in again to continue."
                        Write-Host "Signing in again..." -ForegroundColor Yellow
                        op signin

                        # Clear current batch to prevent re-opening old URLs
                        $urlBatch.Clear()
                        $validUrlCount = 0
                        Write-Progress -Id 2 -Activity "Collecting URLs for next batch" -Completed
                        Write-Host "`nSession restored. Resuming scan..." -ForegroundColor Green
                        continue
                    }

                    # Clear only if still authenticated
                    $urlBatch.Clear()
                    $validUrlCount = 0
                    Write-Progress -Id 2 -Activity "URLs Found" -Completed
                }
            }
        }
    }
}

# Timer End
#$scanEnd = Get-Date
#$duration = $scanEnd - $scanStart

# Export to Excel if chosen
if ($doExportExcel) {
    try {
        $results | Export-Excel -Path $output -BoldTopRow -FreezeTopRow -AutoSize -AutoFilter -Show
        Write-Color "`nExcel file saved to", " $($output)" -Color Cyan, White
    }
    catch {
        Write-Color "`nFailed to save Excel file." -Color Red
        Write-Color "Error: $($_.Exception.Message)" -Color Yellow
    }
}

#Write-Color "Scan start time: ", "$($scanStart.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan, White
#Write-Color "Scan end time: ", "$($scanEnd.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan, White
#Write-Color "`n`nTotal scan time: ", "$($duration.ToString("hh\:mm\:ss"))`n" -Color Cyan, White