<#
.Synopsis
   This script assists in exporting EntraID users along with a list of their attributes.

.EXAMPLE
   .\Update-MobileNumber.ps1

.NOTES
  Version:             1.1
  Author:              Gautam Sharma @ergautamsharma
  Source:              https://github.com/ergautamsharma/EntraID
  Creation Date:       August 04, 2022
  Last Update Date:    August 19, 2022
    Disclaimer: 
        Following scripts come without warranty. 
        This script will update the Mobile number for user on SSPR.
#>

Connect-AzureAD
$allAzureADUser = Get-AzureADUser -All $true -Filter "UserType eq 'Member'"  #| Select-Object -First 1
$Alluserhash = @{}

$TotalItems=$allAzureADUser.Count
$CurrentItem = 0
$PercentComplete = 0

foreach ($useri in $allAzureADUser)
{
    $user = Get-AzureADUser -ObjectId $useri
    Write-Progress -Activity "Exporting - $($user.Mail)" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
    #Write-Host "$($user.Mail)"
    $Alluserhash = @{
        UserPrincipalName = $($user.UserPrincipalName);
        employeeId = $($user.ExtensionProperty.employeeId);
        MailNickName = $($user.MailNickName);
        #DistinguishedName = $($user.ExtensionProperty.onPremisesDistinguishedName);
        Mail = $($user.Mail);
        DisplayName = $($user.DisplayName);
        AccountEnabled = $($user.AccountEnabled);
        City = $($user.City);
        CompanyName = $($user.CompanyName);
        Country =$($user.Country);
        PhysicalDeliveryOfficeName = $($user.PhysicalDeliveryOfficeName)


    }
    #$Alluserhash.GetEnumerator() | Export-Csv -Path C:\Temp\PepsiCo\WS1User-Intune\AzureADUSER.csv -NoTypeInformation -Append
    $AzureADExport = New-Object PSObject -Property $Alluserhash
    #$AzureADExport | Select-Object UserPrincipalName, employeeId, DistinguishedName, Mail, DisplayName, AccountEnabled | Export-Csv -Path "C:\Temp\PepsiCo\WS1User-Intune\Sept-06-23\Sept-19AzureADUser-Export.csv" -NoTypeInformation -Append
    $AzureADExport | Select-Object UserPrincipalName, employeeId, MailNickName, Mail, DisplayName, AccountEnabled, City, CompanyName, Country, PhysicalDeliveryOfficeName | Export-Csv -Path ".\Downloads\GPID.csv" -NoTypeInformation -Append
    $CurrentItem++
    $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
}