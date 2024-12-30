<#
.Synopsis
   This script updates the mobile number for SSPR, bypassing the end user's mobile number registration process for 2FA. 

.EXAMPLE
   .\Update-MobileNumber.ps1

.INPUTS
   The same CSV file is used for creating bulk users via the Azure portal.

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

 Begin
    {
    
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

    #Asking for input file
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = $(Get-Location)
        Filter = 'CSV files (*.csv)|*.csv'
        Title = 'Select the input file'
    }
    $null = $FileBrowser.ShowDialog()

    #validating the Microsoft Graph module installed or not
    $MGISModuleStatus = Get-Module Microsoft.Graph.Identity.Signins -ListAvailable

    if ($null -eq $MGISModuleStatus)
    {
        #Installing Microsoft Graph module 
        Install-Module Microsoft.Graph.Identity.Signins -Scope CurrentUser -ErrorAction SilentlyContinue
        $MGISModuleStatus = Get-Module Microsoft.Graph.Identity.Signins -ListAvailable
        if ($null -eq $MGISModuleStatus)
        {
            [System.Windows.Forms.MessageBox]::Show("Microsoft Graph PowerShell Module is not installed on this system. Install the Microsoft Graph PowerShell Module by running 'Install-Module Microsoft.Graph.Identity.Signins -Scope CurrentUser' in elevated mode and run the powershell command again. `n`n`t`t`tThank You!!!", 'Microsoft Graph Module Not Found')
            Break 
        }

    }
}
Process
    {
    $connect = Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All
    Select-MgProfile -Name beta

    $Users = Get-Content $FileBrowser.FileName | Select-Object -Skip 1 | ConvertFrom-Csv

    foreach ($User in $Users)
    {
        if ($null -ne $User.'Mobile phone [mobile]')
        {
            Write-Host "$($user.'User name [userPrincipalName] Required') mobile number is $($User.'Mobile phone [mobile]')" 
            $validateMobile = (Get-MgUserAuthenticationPhoneMethod -UserId $user.'User name [userPrincipalName] Required').PhoneNumber
            if ($null -eq $validateMobile)
            {
                $update = New-MgUserAuthenticationPhoneMethod -UserId $user.'User name [userPrincipalName] Required' -phoneType "mobile" -phoneNumber $User.'Mobile phone [mobile]'
                Start-Sleep -Seconds 5
                $validateMobile = (Get-MgUserAuthenticationPhoneMethod -UserId $user.'User name [userPrincipalName] Required').PhoneNumber
                if ($null -eq $validateMobile)
                {
                    Write-Host "$($user.'User name [userPrincipalName] Required') mobile number is not set please very the format)" -ForegroundColor Red -BackgroundColor White
                }
                else
                {
                    Write-Host "$($user.'User name [userPrincipalName] Required') mobile number is $($User.'Mobile phone [mobile]') has been updated" -ForegroundColor Blue -BackgroundColor White 
                }
            }
            else
            {
                Write-Host "$($user.'User name [userPrincipalName] Required') mobile number is already updated as $validateMobile" -ForegroundColor Blue -BackgroundColor Yellow 
            }
            
        
        }
    
    }
}
End
    {
        $disconnect = Disconnect-MgGraph
    }