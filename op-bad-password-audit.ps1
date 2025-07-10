<#
.SYNOPSIS
    This script authenticates into the 1Password CLI and audits login credentials stored in a specified vault for weak or temporary password patterns.

.DESCRIPTION
    - Signs in to 1Password using CLI.
    - Lists all login items in the specified vault.
    - For each login item, retrieves the associated username and password.
    - Searches for passwords that match specific weak patterns ("CHANGEME" or "CHANGEME2", case-insensitive).
    - If a weak password is found, displays relevant details in the console and stores them in an array.
    - Exports the findings to an Excel spreadsheet on the user's desktop using the ImportExcel module.

.NOTES
    - Requires 1Password CLI (`op`) to be installed and signed in.
    - Requires the PowerShell `ImportExcel` module to export results.
    - Customize `$vaultName`, `$output`, and regex patterns for other use cases.
    
    Author: Chris Cardi
    Date: 5/3/2025
#>

# Signin
Invoke-Expression $(op signin)

# Personal Parameters
$vaultName = "CHANGEME"
$output = "C:\CHANGEME\BadPasswords.xlsx"

# Delete file if it already exists
if ($output) {
    Remove-Item $output
}

# Get login items
$items = op item list --vault $vaultName --categories Login --format json | ConvertFrom-Json #this makes it an object to retrieve info from

# Array
$results = @()

Write-Host "`nSearching...`n" -ForegroundColor Cyan

foreach ($item in $items) {
    $id = $item.id # Item ID number for that entry
    $title = $item.title # Name of Titled entry

    # Retrieve username and password
    $fields = op item get $id --vault $vaultName --fields label=username,label=password --format json | ConvertFrom-Json 
    $username = ($fields | Where-Object { $_.label -eq "username" }).value
    $password = ($fields | Where-Object { $_.label -eq "password" }).value

    # Check for matching pattern
    if ($password -match '(?i)CHANGEME' -or $password -match '(?i)CHANGEME2') { 
        Write-Color "Match found in:", " $($title)" -Color White, Green
        Write-Host "Username: $username"
        Write-Host "--------------------------"
        # Collect results wanted in array using hash table key pairs
        $results += [PSCustomObject]@{
            Title = $title
            Username = $username
        }
    }
}

$results | Export-Excel -Path $output -AutoSize -WorksheetName "Matches" -Show
Write-Color "`nExcel file saved to", " $($output)`n" -color White, Cyan
