<#
.SYNOPSIS
Automates the tagging of CrowdStrike Falcon hosts based on Active Directory group membership sourced from a SharePoint list.

.DESCRIPTION
This script performs the following tasks:
- Connects to SharePoint Online to retrieve a list of AD security groups and associated CrowdStrike tags.
- Queries Active Directory for recent group changes and retrieves group membership.
- For each computer object in the group, checks CrowdStrike Falcon for a matching host.
- Applies a defined Falcon Grouping Tag to the host if it is not already tagged.
- Logs detailed processing results to an Excel file with categorized worksheets (Information, Warnings, Errors).
- Uploads the report to the configured SharePoint folder.

Note: Email reporting has been deprecated and removed due to lack of support for `Send-EmailMessage` in PowerShell 7+.

.REQUIREMENTS
- PnP PowerShell Module
- ImportExcel Module
- Active Directory Module
- Falcon PowerShell Module (custom from CrowdStrike)
#>


Param(
    $ConfigurationFile = "$PSScriptRoot\config.json"
)

#Region Functions
function Connect-FalconCloud {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string]$FalconClientID,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\w{40}$')]
        [string]$FalconClientSecret,

        [Parameter()]
        [ValidateSet('us-1', 'us-2', 'us-gov-1', 'eu-1')]
        [string]$FalconCloud = 'XXXXXX'
    )
    $FalconToken = Test-FalconToken -ErrorAction SilentlyContinue
    if (($FalconToken).token -eq $false -or $null -eq $FalconToken) {
        Request-FalconToken -ClientId $FalconClientID -ClientSecret $FalconClientSecret -Cloud $FalconCloud
    }
    Test-FalconToken
}
#EndRegion Functions

if ($PSScriptRoot -eq '') {
    $testing = $true
    $ConfigurationFile = 'XXXXXX'
    if ((Test-Path $ConfigurationFile) -eq $false) {
        $ConfigurationFile = 'XXXXXX'
    }
}

if (Test-Path $ConfigurationFile) {
    $Configuration = Get-Content $ConfigurationFile | ConvertFrom-Json
} else {
    Write-PSFMessage -Level Critical -Message "Unable to find configuration File, Script halting" -Tag Initialization, Error
    Write-Error "Unable to find configuration File, Script halting" -ErrorAction Stop
}

$HelperPath = $Configuration.CommonConfiguration.HelperPath
. "$helperPath\XXXXXX.ps1"

$PNPClientID = $Configuration.CommonConfiguration.PNPClientID
$PNPThumbprint = $Configuration.CommonConfiguration.PNPThumbprint
$TenantName = $Configuration.CommonConfiguration.TenantName
$SharePointBaseURL = $Configuration.CommonConfiguration.SharePointBaseURL
$SharePointFolder = $Configuration.CommonConfiguration.SharePointFolder

$FalconClientID = $Configuration.CommonConfiguration.ClientID
$FalconClientSecret = (Get-XXXXXX -SecretStorePasswordPath "$env:XXXXXX" -secretName $Configuration.CommonConfiguration.APICredName -ReturnSecureString) | ConvertFrom-SecureString -AsPlainText
$FalconCloud = $Configuration.CommonConfiguration.Region

$ProcessingMessages = [System.Collections.Generic.List[Object]]::new()

try {
    Connect-PnPOnline -ClientId $PNPClientID -Url $SharePointBaseURL -Tenant $TenantName -Thumbprint $PNPThumbprint
    Write-PSFMessage -Level Host "Connected to Sharepoint"
} catch {
    Write-PSFMessage -Level Critical "Unable to connect to sharepoint exiting"
    break
}

$DaysToLookBack = 14
$today = Get-Date 

$Groups = Get-PnPListItem -List "CrowdStrike Group Tagging"
foreach ($group in $groups) {
    $SharepointValues = $group.FieldValues
    $GroupName = $SharepointValues.ADgroupName
    $Domain = $SharepointValues.Domain
    $CrowdStrikeTag = $SharepointValues.Title

    $ADGroup = Get-ADGroup -Server $domain -Filter "name -eq '$groupname'" -Properties whenChanged
    if ($ADGroup.whenChanged -gt ($today).AddDays(-$DaysToLookBack)) {
        Write-Host -ForegroundColor Cyan "Processing group $($adgroup.name)" -NoNewline
        $ADGroupMembers = Get-ADGroupMember -Server $Domain $ADgroup.DistinguishedName -Recursive
        Write-Host -ForegroundColor Cyan "."
        if ($ADGroupMembers) {
            foreach ($Computer in ($ADGroupMembers | Where-Object objectclass -EQ 'Computer')) {
                Write-Host -ForegroundColor Green "Processing computer $($Computer.name)" -NoNewline
                $Adcomputer = Get-ADComputer $Computer.DistinguishedName -Server $domain
                Write-Host -ForegroundColor Green "."
                if ($adComputer.enabled -eq $true) {
                    Write-Host "Finding Falcon object" -NoNewline
                    Connect-FalconCloud -FalconClientID $FalconClientID -FalconClientSecret $FalconClientSecret | Out-Null
                    Write-Host "." -NoNewline
                    $Falconhost = Get-FalconHost -Detailed -Filter "hostname:['$($Adcomputer.name)']" | Sort-Object last_seen -Descending | Select-Object -First 1
                    Write-Host "."
                    if ($Falconhost) {
                        if ($Falconhost.tags -contains "FalconGroupingTags/$CrowdStrikeTag") {
                            Write-PSFMessage -Level Host "tag $crowdstrikeTag already assigned to computer: $($adcomputer.name) skipping"
                            $ProcessingMessages.add([PSCustomObject]@{
                                Category = 'Information'
                                Object   = $falconhost.Hostname
                                Result   = 'Skipped'
                                message  = "Existing tag $crowdstrikeTag on $($adcomputer.name) in domain: $domain"
                            })
                        } else {
                            Write-PSFMessage -Level host "Adding Tag $CrowdStrikeTag to $($adcomputer.name)"
                            try {
                                $result = Add-FalconGroupingTag -Id $Falconhost.device_id -Tag "FalconGroupingTags/$crowdstrikeTag" 
                                $ProcessingMessages.add([PSCustomObject]@{
                                    Category = 'Information'
                                    Object   = $falconhost.Hostname
                                    Result   = 'Added'
                                    message  = "Added $crowdstrikeTag to $($adcomputer.name) in domain: $domain"
                                })
                            } catch {
                                Write-PSFMessage -Level Error "Errors Adding Tag $CrowdStrikeTag to $($adcomputer.name), $($Error[0])"
                                $ProcessingMessages.add([PSCustomObject]@{
                                    Category = 'Error'
                                    Object   = $falconhost.Hostname
                                    Result   = 'Failure'
                                    message  = "Error adding tag to Falcon object. Message $($Error[0])"
                                })
                            }
                        }
                    } else {
                        Write-PSFMessage -Level Warning "Unable to find computer $($Computer.DistinguishedName) in crowdstrike"
                        $ProcessingMessages.add([PSCustomObject]@{
                            Category = 'Warning'
                            Object   = $computer.name
                            Result   = 'Information'
                            message  = "Computer account $($computer.distinguishedName) not found in Crowdstrike so skipping"
                        })
                    }
                } else {
                    Write-PSFMessage -Level Warning "$($Computer.DistinguishedName) is disabled not checking."
                    $ProcessingMessages.add([PSCustomObject]@{
                        Category = 'Warning'
                        Object   = $computer.name
                        Result   = 'Information'
                        message  = "Computer account $($computer.distinguishedName) is disabled so being excluded from processing"
                    })
                }
            }
        } else {
            Write-PSFMessage -Level Warning "Group is Empty"
            $ProcessingMessages.add([PSCustomObject]@{
                Category = 'Warning'
                Object   = $groupName
                Result   = 'Information'
                message  = "Found group $groupname but group has no direct members. Nested groups are not supported."
            })
        }
    } else {
        if ($null -ne $adgroup) {
            Write-PSFMessage -Level Warning "Unable to find Group"
            $ProcessingMessages.add([PSCustomObject]@{
                Category = 'Error'
                Object   = $groupName
                Result   = 'Failure'
                message  = "Unable to find group $groupName in Active Directory by querying domain $Domain"
            })
        } else {
            $ProcessingMessages.add([PSCustomObject]@{
                Category = 'Information'
                Object   = $groupName
                Result   = 'Information'
                message  = "Group $groupname has not been updated in $daystolookback so skipping."
            })
        }
    }
}

$ErrorMessages = @($ProcessingMessages | Where-Object Category -EQ 'Error')
$WarningMessages = @($ProcessingMessages | Where-Object Category -EQ 'Warning')
$InformationMessages = @($ProcessingMessages | Where-Object Category -EQ 'Information')

$ExcelFileDate = get-date -Format 'dd-MMM-yyyy hh-mm-ss'
$filename = [System.IO.Path]::GetTempFileName()
$ExcelFile = [System.IO.Path]::ChangeExtension($filename, ".xlsx")
$ExcludeExcelAttributes = @()

if ($InformationMessages.count -gt 0){
    $ExcelPackage = $InformationMessages | Export-Excel -path $ExcelFile -WorksheetName "Information" -TableName "Information" -ExcludeProperty $ExcludeExcelAttributes -AutoSize -FreezeTopRowFirstColumn -PassThru
}
if ($WarningMessages.count -gt 0){
    $ExcelPackage = $WarningMessages | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Warnings" -TableName "Warnings" -ExcludeProperty $ExcludeExcelAttributes -AutoSize -FreezeTopRowFirstColumn -PassThru -MoveToStart
}
if ($ErrorMessages.count -gt 0){
    $ExcelPackage = $ErrorMessages | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Errors" -TableName "Errors" -ExcludeProperty $ExcludeExcelAttributes -AutoSize -FreezeTopRowFirstColumn -PassThru -MoveToStart
}

if ($WarningMessages.count -gt 0 -or $ErrorMessages.count -gt 0 -or $InformationMessages.count -gt 0){
    Close-ExcelPackage $ExcelPackage
    $ExcelPackage = $null
    $NewFileName = "$ExcelFileDate.xlsx"
    try {
        Add-PnPFile -Path $ExcelFile -Folder "$SharePointFolder" -NewFileName $NewFileName
        Write-PSFMessage -Level Host -Message "    Excel file written to $SharePointBaseURL/$SharePointFolder/$newFilename " -tag Processing, Info, SharepointUpload
    } catch {
        Write-PSFMessage -Level Warning "Error with uploading Excel file to $SharePointBaseURL/$SharePointFolder/$newFilename" -tag Processing, Error, SharepointUpload
    }
}
