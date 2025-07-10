<#
.SYNOPSIS
    Script to check if an IP address is malicious using AIPDB's bulk checker tool.

.DESCRIPTION
    Script will authenticate to MS Azure tenant, run a KQL query used in threat hunting, and take the IP Addresses from the results and export it to a file.  
    
    It will then run AIPDB's bulk-checker tool against AIPDB via API to see if any of the IP addresses in the results file is malicious.  If not, then it will automatically assign the tickets to myself and close out the ticket with the requested information.  It will then display the requested information of all closed tickets. 

    If a malicious IP is found, the program identifies the IP addresses and then exits with the intention that manual investigation would be necessary.  

.NOTES
    Author: Chris Cardi
    Date: 7/10/2025

    *Any specifically identifying code has been changed to a random value for security.*
#>

#Region AUTHENTICATE

# ELEVATE ACCOUNT FIRST!!!
# CONNECT ACCOUNT
Connect-AzAccount

# Retrieve secrets
$ApiKey = Get-Secret -Name "SECRETNAME1" | ConvertFrom-SecureString -AsPlainText
$WorkspaceName = Get-Secret -Name "SECRETNAME2" | ConvertFrom-SecureString -AsPlainText
$WorkspaceID = Get-Secret -Name "SECRETNAME3" | ConvertFrom-SecureString -AsPlainText
$WorkspaceRG = Get-Secret -Name "SECRETNAME4" | ConvertFrom-SecureString -AsPlainText
$Subscription = Get-Secret -Name "SECRETNAME5" | ConvertFrom-SecureString -AsPlainText

# Setup Sub
set-azcontext -Subscription $Subscription
#EndRegion AUTHENTICATE

#Region CODE
# Paths to output files
$OutputPath = "C:\PATH_TO\FILE"
$OutputPath2 = "C:\PATH_TO\FILE"

# Cleanup old output files from previous runs
if (Test-Path $OutputPath) { 
    Remove-Item $OutputPath -Force 
}
if (Test-Path $OutputPath2) { 
    Remove-Item $OutputPath2 -Force 
}

# KQL rule of specific incident
# <<< NOTE: IF YOU CHANGE TIMERANGE HERE, YOU HAVE TO CHANGE TIMERANGE IN LINES 179 and 216!!!!! >>>
$phone = "SigninLogs
| where TimeGenerated > ago(24h)
| where MfaDetail contains 'Phone'
| where LocationDetails.state <> 'STATE'
| where LocationDetails.city <> 'CITY'
| where LocationDetails !contains 'CITY'
| where LocationDetails !contains 'CITY'
| where DeviceDetail.isManaged <> true
    and IPAddress !contains 'IP'
    and IPAddress !contains 'IP'
    and IPAddress !contains 'IP'
    and IPAddress !contains 'IP'
    and IPAddress !contains 'IP'
| sort by TimeGenerated desc
| summarize by IPAddress"

$ignore = "SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == NUMBERS
| where Status.additionalDetails == 'MFA denied; user did not respond to mobile app notification'
| where LocationDetails !contains 'STATE'
| where IPAddress !startswith 'IP'
| where IPAddress !contains 'IP'
| where IPAddress !contains 'IP'
| where IPAddress != 'IP'
| where LocationDetails !contains 'STATE'
| where LocationDetails !contains 'CITY'
| where LocationDetails.city <> 'CITY'
| where DeviceDetail.trustType <> 'Hybrid Azure AD joined'
| sort by TimeGenerated desc
| summarize by IPAddress"

$ispDetection = "SigninLogs
| where TimeGenerated > ago(24h)
| where MfaDetail.authMethod contains 'Phone'
| where IPAddress !contains 'IP'
| where IPAddress !contains 'IP'
| join kind=inner 
BehaviorAnalytics on UserPrincipalName
| where DevicesInsights.ISP !has 'ISPNAME'
| where DevicesInsights.ISP !has 'ISPNAME'
| where EventSource contains 'SOURCENAME'
| where ActivityType == 'LogOn'
| where SourceIPAddress !contains 'IP'
| where SourceIPAddress !contains 'IP'
| where SourceDevice == ''
|project TimeGenerated, UserPrincipalName, DevicesInsights.ISP, SourceIPAddress, IPAddress, ActivityType, MfaDetail, RiskLevelDuringSignIn
| summarize by IPAddress"

# Run the query
$kqlQueryPhone = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $phone
$kqlQueryIgnoreMFA = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $ignore
$kqlQueryISPdetection = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $ispDetection

# Take the results from query, remove first row (which is the name of the column, called "IP") and write to file specified in $OutputPath
$kqlQueryPhone.Results | ConvertTo-Csv | select-object -Skip 1 | Out-File $OutputPath -Force -Append
$kqlQueryIgnoreMFA.Results | ConvertTo-Csv | Select-Object -Skip 1 | Out-File $OutputPath -Force -Append
$kqlQueryISPdetection.Results | ConvertTo-Csv | Select-Object -Skip 1 | Out-File $OutputPath -Force -Append

# Stop script if file doesn't exist
if (!$OutputPath) {
    exit 0
}

# Create empty array to collect Abused IPs
$AbusedIPs = @()

# Modified snippet of code from AIPDB tool (lines 117-135) to bulk query IP addresses from $OutputPath
$jsonTempPath = New-TemporaryFile # Creates a temporary file during IP check
$foundBadIP = $false # Malicious IP flag
Write-Color -Text "Starting IP check... " -Color Blue -BackGroundColor White
Write-Host ""
Import-csv $outputPath -Header "IP" | ForEach {
    if ($_.IP -as [ipAddress] -as [Bool]) { # Check if it's an IP Address
        Invoke-WebRequest -Uri ("https://api.abuseipdb.com/api/v2/check?ipAddress=$($_.IP)") -Headers @{ 'Accept' = 'application/json'; 'Key' = $ApiKey } -usebasicparsing | add-content -path $jsonTempPath # This is the actual API request
        $abuse = Get-content $jsonTempPath | ConvertFrom-Json | select -ExpandProperty Data | select abuseConfidenceScore, ipAddress
        # If Abuse score not equal to "0" then add to AbusedIPs array and flag "foundBadIP" to $true
        if ($abuse.abuseConfidenceScore -ne "0" ) {
            Write-Color -Text "Found", " $($abuse.ipAddress)" -Color White, Red
            $AbusedIPs += $abuse.ipAddress
            $foundBadIP = $true
        }
    } else {
        throw "$($_.IP) is not a valid IP!" # Throw an error showing which IP is invalid
    }       
Remove-Item $jsonTempPath.FullName -Force #Remove temp file  
}

# If no malicious IP was found, report "All clear!"
if ($foundBadIP -eq $false) { 
    Write-Color -Text "
    -=-=-=-=-=-=-=
    | All clear! |
    -=-=-=-=-=-=-=`n" -Color Green
} else {
    Write-PSFHostColor -Level Host -String "Please check IPs that were found." -DefaultColor White
    exit 0
}


#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 
# ABOVE CODE WILL RUN THE REPORT AND CHECK FOR IPS    #
#                                                     #
# BELOW CODE WILL ACT ON INCIDENTS AND CLOSE THEM OUT #
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Set of properties to gather per incident
$Properties = @(
    'Title',
    'Number',
    'Classification',
    'Status',
    'OwnerAssignedTo',
    'OwnerType',
    'OwnerObjectId',
    'OwnerEmail',
    'OwnerUserPrincipalName',
    'CreatedTimeUtc',
    'Id'
)

Write-PSFHostColor -level Host -String "Grabbing New Incidents.  Please wait..." -DefaultColor Cyan

# Grab first 200 incidents with keywords "phone" and "ignore"
$SecurityIncidents = Get-AzSentinelIncident -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName 
    | select -Property $Properties
    | where { $_.Title -like "*phone*" -or $_.Title -like "*ignore*" } # Change this to reflect desired rule names
    | where Status -eq "New" | select -first 200

# Get New Security incidents within the last 24 hours
$endTime = (Get-Date).AddDays(-1) # CHANGE TIME HERE IF NECESSARY
$NewSecurityIncidents = $SecurityIncidents | where { $_.CreatedTimeUtc -ge $endTime }

# FUNCTION to isolate incident ID number from the rest of the path
function GetId {
    param (
        [string]$path
    )
    $index = $path.LastIndexOfAny('/')
    if ($index -ge 0) {
        $result = $path.Substring($index + 1)
        return $result
    } else {
        return $path
    }
}

# Check to see if new incidents are found
if ($NewSecurityIncidents.count -gt 0) {
Write-PSFHostColor -Level Host -String "Found $($NewSecurityIncidents.count) new." -DefaultColor White
Start-Sleep -Seconds 4
} else {
    Write-PSFHostColor -String "No new incidents found.`n" -DefaultColor White
    exit 0  #ends script
}

# If "FoundBadIP" flag was not triggered, all is well and code will continue
# Continue to close ticket
$UpdateComplete = $false
if ($foundBadIP -eq $false) {
    if ($NewSecurityIncidents.Count -eq "1") {
        Write-PSFHostColor -Level Host "Updating incident entry..." -DefaultColor Cyan
    } else {
        Write-PSFHostColor -Level Host -String "Updating incident entries..." -DefaultColor Cyan
    }
    foreach ($incident in $NewSecurityIncidents) {
        # If the incident is within the last 24 hours
        if ($incident.CreatedTimeUtc -ge (get-date).AddDays(-1) -and $NewSecurityIncidents.count -ne "0") { # CHANGE TIME HERE IF NECESSARY
            $Getid = GetId $incident.Id   #Function is assigned to variable here then called (line 219)
            # Fill in your own personal information in "OwnerAssignedTo, OwnerObjectId and OwnerUserPrincipalName"
            Update-AzSentinelIncident -Id $Getid -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -Status Closed -OwnerAssignedTo 'USERNAME' -OwnerObjectId "OWNEROBJECTID" -OwnerUserPrincipalName "OWNERUSERPRINCIPALNAME" -Confirm:$false -Classification 'BenignPositive' -Title "$($incident.Title)" -Severity 'Informational' -ClassificationReason 'SuspiciousButExpected' | select Title, Number, Severity, Classification, OwnerAssignedTo, Status
            # Trigger "UpdateComplete" flag
            $UpdateComplete = $true
        } 
    }
}

# If UpdateComplete flag was triggered, print status
if ($UpdateComplete = $true) {
    if ($NewSecurityIncidents.Count -eq 1){
    Write-Color "Updated ", "$($NewSecurityIncidents.Count)", " entry.`n`n" -C Cyan, White, Cyan
    } else {
        Write-Color "Updated ", "$($NewSecurityIncidents.Count)", " entries.`n`n" -C Cyan, White, Cyan
    }
}
#EndRegion CODE


#Region NOTES
<#
# Options available from original code in tool
Get-content $jsonTempPath | ConvertFrom-Json | select -ExpandProperty Data | select ipAddress, abuseConfidenceScore, isp, domain, countryCode, totalReports, lastReportedAt | ConvertTo-CSV -NoTypeInformation | add-content $outputPath2  #Create CSV output file

# Uses a different query system if using '-Filter' Parameter
Get-AzSentinelIncident -ResourceGroupName $workspaceRG -workspaceName $workspaceName -Filter "properties/Status eq 'New'"

# Filter for multiple conditions using the '-Filter' Parameter
GET ~/users?$filter=startswith(displayName,'mary') or startswith(givenName,'mary') or startswith(surname,'mary') or startswith(mail,'mary') or startswith(userPrincipalName,'mary')

Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" -ArgumentList $OutputPath2
#>

#EndRegion NOTES

