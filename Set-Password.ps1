<#
.SYNOPSIS
  This script is used for set new password for Azure AD user.

.DESCRIPTION
  This script is used for set new password for Azure AD user.

.INPUTS
  Input.csv file will be used to supply the list of upn. file header should be like below

  UserPrincipalName

  
.OUTPUTS
  log file as Output will be available as following:
  Output-<DateTimeStamp>.log - log file will be created
  

.EXAMPLE
    .\Set-Password.ps1

.NOTES
  Version:             1.1
  Author:              Gautam Sharma @ergautamsharma
  Source:              https://github.com/ergautamsharma/EntraID
  Creation Date:       March 04, 2023
  Last Update Date:    March 19, 2023

#>

#Function for log writing
Function Write-Log {
  param(
      [Parameter(Mandatory = $true)]
      [string] $message,
      [Parameter(Mandatory = $false)]
      [ValidateSet("INFO","WARN","ERROR")]
      [string] $level = "INFO",
      [Parameter(Mandatory = $false)]
      [string] $logFile = $logFile
  )
  # Create timestamp
  $timestamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")

  # Append content to log file
  Add-Content -Path $logFile -Value "$timestamp [$level] - $message"
}


#Function for get input file
Function Get-FileName{  
     [System.Reflection.Assembly]::LoadWithPartialName(“System.windows.forms”) | Out-Null
     $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
     $OpenFileDialog.filter = “CSV Files (*.csv) | *.csv”
     $OpenFileDialog.ShowDialog() | Out-Null
     $path = $OpenFileDialog.filename
     if ($path -notmatch ".csv")
     {
         $path = "Nothing"
     }
     return $path
}

#Module required / connect
#$cred = Get-Credential
Connect-AzureAD #-Credential $cred

#Main Function 
function Main
{
    
    Write-Log -message "Starting..." -level INFO -logFile $logFile
    $InputCSV = Get-FileName
    Write-Log -message "Input file name is $InputCSV" -logFile $logFile -level INFO
    $collection = Import-Csv $InputCSV
    $headervalidation = $collection | Get-Member | Where-Object {$_.name -EQ "UserPrincipalName"}

    if ($headervalidation)
    {
        $usersCount = ($collection | Measure-Object).Count
        $Message = "Total users are $usersCount."
        Write-Log -message $Message -level INFO -logFile $logFile

        foreach ($item in $collection)
        {
            $pct = "0"
            $pcti = $pcti + 1
            $pct = ($pcti/$usersCount) * 100
        
            #Input required
            $UPN = $item.UserPrincipalName
            $NewPass = 'Welcome@123'
            $password = ConvertTo-SecureString $NewPass -AsPlainText -Force

            #validating user
            $AzADuser = Get-AzureADUser -ObjectId $UPN

            Write-Progress -Activity "Proforming changing password" -Status "Processing User $pcti of $usersCount - $UPN" -PercentComplete $pct
            if ($AzADuser)
            {
                #Change password for Azure AD User
                Set-AzureADUserPassword -ObjectId  $AzADuser.ObjectId -Password $password -ForceChangePasswordNextLogin $true
                Write-Log -message "Password has been changed for: $UPN" -level INFO -logFile $logFile

            }
            else
            {
                Write-Log -message "User Not Found - $UPN" -level ERROR -logFile $logFile
            }
       }
       }
    else
    {
        $Message = "Input file header is not correct. Please use 'UserPrincipalName' as header of CSV input file"
        Write-Error -Message $Message
        Write-Log -message $Message -level ERROR -logFile $logFile
    } 

    Write-Log -message "All user(s) operation has been executed" -level INFO -logFile $logFile

}

#Global Variable
$DateTimeStamp = Get-Date -Format ddMMyyhhmm
$Path = (Get-Location).ProviderPath
$logFile = $Path + "\Output-" + $DateTimeStamp + ".log"
$DateTimeZone = Get-TimeZone
Write-Log -message "Log DateTime format is Date/Month/Year Hour:Minute:Second" -level INFO -logFile $logFile
Write-Log -message "Time Zone is $($DateTimeZone.StandardName) - $($DateTimeZone.DisplayName)" -level INFO -logFile $logFile
Write-Log -message "log file path is $logFile" -level INFO -logFile $logFile
[int]$pcti = "0"
 
Main

#Disconnect Cloud session
Disconnect-AzureAD
