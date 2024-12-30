<#
.SYNOPSIS
  This script is designed to facilitate the migration of Entra users, including their group memberships, from one Entra ID tenant to another. 

.DESCRIPTION
  This script is designed to facilitate the migration of Entra users, including their group memberships, from one Entra ID tenant to another. 

.INPUTS
  Input.txt file will be used to supply the list of upn
  
.OUTPUTS
  Output will be available as following:
  AzureADMigrationStatus-<DateTimeStamp>.csv - Migrations users status
  AzureADMigrationStatus-<DateTimeStamp>.log - log file will be created
  

.EXAMPLE
    .\Migrate-AzureAD.ps1 -DestinationDomain "<Tergate Domain>"

.EXAMPLE
    .\Migrate-AzureAD.ps1 -DestinationDomain "<Tergate Domain>" -UserPrincipalName <User1-UPN>,<User2-UPN>

.EXAMPLE
    .\Migrate-AzureAD.ps1 -DestinationDomain "<Tergate Domain>" -Verbose

.EXAMPLE
    $SrcCred = Get-Credential -Message "Please enter Source tenant Creadential"
    $DstCred = Get-Credential -Message "Please enter Destination tenant Creadential"
    .\Migrate-AzureAD.ps1 -UserPrincipalName <SourceTenantUser> -DestinationDomain "<DestinationDomain>" -SourceTenantCreadential $SrcCred -DestinationTenantCreadential $DstCred


.NOTES
  Version:             1.1
  Author:              Gautam Sharma @ergautamsharma
  Source:              https://github.com/ergautamsharma
  Creation Date:       January 20, 2023
  Last Update Date:    January 23, 2023

#>

Param
    (
        [Parameter(Mandatory=$false)]
	  [ValidateScript({ if ($_ -match '@') { return $true }; throw 'Doamin must contain @.' })]
        $UserPrincipalName,
        [Parameter(Mandatory=$false)]
        $SourceTenantCreadential,
        [Parameter(Mandatory=$false)]
        $DestinationTenantCreadential,
        [Parameter(Mandatory=$true)]
        [ValidateScript({ if ($_ -notmatch '@') { return $true }; throw 'Doamin must not contain @.' })]
        $DestinationDomain

        )

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
 [System.Reflection.Assembly]::LoadWithPartialName(“System.windows.forms”) |
 Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 $OpenFileDialog.filter = “Text Files (*.txt) | *.txt”
 $OpenFileDialog.ShowDialog() | Out-Null
 $path = $OpenFileDialog.filename
 if ($path -notmatch ".txt")
 {
     $path = "Nothing"
 }
 return $path
}

#Function for get user details
Function Get-SrcAzureADUser
{
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        $UPN
        )
    Begin {
        Write-Verbose "In Begin Block: Get-SrcAzureADUser"
        [hashtable]$UserDetails = @{}
        #[hashtable]$SourceAzureADGroupDetail = @{}
    }
    Process{
        Write-Verbose "In Process Block: Get-SrcAzureADUser"
        
        $User = Get-AzureADUser -ObjectId $UPN

        $UserDetails = @{
            UserPrincipalName = $upn;
            DisplayName = $user.DisplayName;
            GivenName = $user.GivenName;
            Surname = $user.Surname;
            MailNickname = $user.MailNickname;
            JobTitle = $user.JobTitle;
            Department = $user.Department;
            Company = $user.CompanyName;
            UserType = $user.UserType;
            AccountEnabled = $user.AccountEnabled;
            SignInName = $user.SignInName;
            StreetAddress = $user.StreetAddress;
            City = $user.City;
            State = $user.State;
            PostalCode = $user.PostalCode;
            Country = $user.Country;
            PhysicalDeliveryOfficeName = $User.PhysicalDeliveryOfficeName;
            TelephoneNumber = $User.TelephoneNumber

            }
        
        }
        
        
    End{
        Write-Verbose "In End Block: Get-SrcAzureADUser"
        #Write-Log -message "SourceAzureADGroupDetail: $SourceAzureADGroupDetail `nSourceAzureADGroupOwner: $SourceAzureADGroupOwner" -logFile $logFile -level INFO
        Write-Verbose "SourceAzureADGroupDetail: $SourceAzureADGroupDetail"
        #return $UserDetails, $SourceAzureADGroupDetail #, $SourceAzureADGroupOwner
        return $UserDetails
    }


}

#Function for get user details
Function Get-SrcAzureADUserGroup
{
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        $UPN
        )
    Begin {
        Write-Verbose "In Begin Block: Get-SrcAzureADUserGroup"
        [hashtable]$UserDetails = @{}
        #[hashtable]$SourceAzureADGroupDetail = @{}
    }
    Process{
        Write-Verbose "In Process Block: Get-SrcAzureADUserGroup"
        
        $User = Get-AzureADUser -ObjectId $UPN

        $Usergroups = Get-AzureADUserMembership -ObjectId $User.ObjectId | Where-Object {$_.SecurityEnabled -eq $true} -ErrorAction SilentlyContinue
        #Write-Verbose "Usergroups Variable value: $Usergroups"
        
        if ($null -ne $Usergroups)
        {
            #$groups = @()
            $SourceAzureADGroupDetail = @()
            #$groups = foreach ($Usergroup in $Usergroups)
            $SourceAzureADGroupDetail = foreach ($Usergroup in $Usergroups)
            
                 {
                     Get-AzureADMSGroup -Id $Usergroup.ObjectId | Select-Object DisplayName, Description, MailEnabled, MailNickname, SecurityEnabled, IsAssignableToRole, Visibility
                 }
            #$SourceAzureADGroupDetail = $groups
            Write-Verbose "user is part of: $SourceAzureADGroupDetail"
            Write-Verbose "User ($UPN) member of: $($SourceAzureADGroupDetail.DisplayName)"
            Write-Log -message "User ($UPN) member of: $($SourceAzureADGroupDetail.DisplayName)" -level INFO -logFile $logFile
            <#$SourceAzureADGroupDetail = foreach ($group in $groups)
                {
                    $SourceGroupDetail = @{
                        DisplayName = $group.DisplayName
                        Description = $group.Description
                        MailEnabled = $group.MailEnabled
                        MailNickname = $group.MailNickname
                        SecurityEnabled = $group.SecurityEnabled
                        IsAssignableToRole = $group.IsAssignableToRole
                        Visibility = $group.Visibility
    
                    }
                    New-Object PSObject -Property $SourceGroupDetail

                }
            <# $SourceAzureADGroupOwner = foreach ($Usergroup in $Usergroups)
                  {
                      Get-AzureADGroupOwner -ObjectId $Usergroup.ObjectId | Where-Object {$_.UserPrincipalName -match $User.UserPrincipalName} | Select-Object DisplayName
                  }
            if ($null -eq $SourceAzureADGroupOwner)
            {
                $SourceAzureADGroupOwner = "NoOwnershipWithAnyGroup"
            }#>
        }
        
        else
        {
            $SourceAzureADGroupDetail = "NotPartOfAnyGroup"
        }


    }
    End{
        Write-Verbose "In End Block: Get-SrcAzureADUserGroup"
        #Write-Log -message "SourceAzureADGroupDetail: $SourceAzureADGroupDetail `nSourceAzureADGroupOwner: $SourceAzureADGroupOwner" -logFile $logFile -level INFO
        Write-Verbose "SourceAzureADGroupDetail: $SourceAzureADGroupDetail"
        #return $UserDetails, $SourceAzureADGroupDetail #, $SourceAzureADGroupOwner
        return $SourceAzureADGroupDetail
    }


}

#Function for Random password generator
Function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4,[int]::MaxValue)]
        [int] $length,
        [int] $upper = 1,
        [int] $lower = 3,
        [int] $numeric = 4,
        [int] $special = 0
    )
    if($upper + $lower + $numeric + $special -gt $length) {
        throw "number of upper/lower/numeric/special char must be lower or equal to length"
    }
    $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lCharSet = "abcdefghijklmnopqrstuvwxyz"
    $nCharSet = "0123456789"
    $sCharSet = "/*-+,!?=()@;:._"
    $charSet = ""
    if($upper -gt 0) { $charSet += $uCharSet }
    if($lower -gt 0) { $charSet += $lCharSet }
    if($numeric -gt 0) { $charSet += $nCharSet }
    if($special -gt 0) { $charSet += $sCharSet }
    
    $charSet = $charSet.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
    $rng.GetBytes($bytes)
 
    $result = New-Object char[]($length)
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
    }
    $password = (-join $result)
    $valid = $true
    if($upper   -gt ($password.ToCharArray() | Where-Object {$_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
    if($lower   -gt ($password.ToCharArray() | Where-Object {$_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
    if($numeric -gt ($password.ToCharArray() | Where-Object {$_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
    if($special -gt ($password.ToCharArray() | Where-Object {$_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
 
    if(!$valid) {
         $password = Get-RandomPassword $length $upper $lower $numeric $special
    }
    return $password
}

#Function for Create User
Function Create-DstAzureADUser
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [hashtable]$User,
        [Parameter(Mandatory=$true)]
        $NewPass,
        [Parameter(Mandatory=$true)]
        $DestinationDomain

        )
    Begin {
        Write-Verbose "In Begin Block: Create-DstAzureADUser"
        $srcUserPrincipalName = $User.UserPrincipalName
        $dstUserPrincipalNameAlias = $srcUserPrincipalName -split "@" | Select-Object -First 1
        $dstUserPrincipalName = $dstUserPrincipalNameAlias + "@" + $DestinationDomain
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = $NewPass
        Write-Verbose "Destination domain: $DestinationDomain & $dstUserPrincipalName" 
        Write-Log -message "Destination domain: $DestinationDomain & Destination UPN: $dstUserPrincipalName" -level INFO -logFile $logFile

    }
    Process{
        Write-Verbose "In Process Block: Create-DstAzureADUser"
        try
        {
            $newUser = New-AzureADUser -DisplayName $user.DisplayName `
                                   -MailNickname $user.MailNickname `
                                   -PasswordProfile $PasswordProfile `
                                   -UserPrincipalName $dstUserPrincipalName `
                                   -AccountEnabled $user.AccountEnabled -ErrorAction Stop
            Set-AzureADUser -ObjectId $newUser.ObjectId -Department $user.Department `
                           -JobTitle $user.JobTitle -City $User.City -Country $User.Country -GivenName $User.GivenName `
                           -PhysicalDeliveryOfficeName $User.PhysicalDeliveryOfficeName -Company $user.Company `
                           -StreetAddress $User.StreetAddress -Surname $User.Surname -TelephoneNumber $User.TelephoneNumber -ErrorAction Stop
            $Return = "$dstUserPrincipalName has been created in destination tenant and password is: $NewPass"
            $ReturnStatus = "Completed"
            return $Return, $ReturnStatus
        }
        catch 
        {
            $return = "$srcUserPrincipalName user failed crated on Destination Tenant`n"
            $return += "`nError Message: $($_.Exception.Message)"
            $return += "`nError in Line: $($_.InvocationInfo.Line)"
            $return += "`nError in Line Number: $($_.InvocationInfo.ScriptLineNumber)"
            $return += "`nError Item Name: $($_.Exception.ItemName)"
            $ReturnStatus = "FailedOrPartiallyFailed"
            return $return, $ReturnStatus
        }
    }
}

#Function for Create User Group
Function Create-DstAzureADUserGroup
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [hashtable]$User,
        [Parameter(Mandatory=$true)]
        $ADGroups,
        [Parameter(Mandatory=$false)]
        $ADGroupsOwners,
        [Parameter(Mandatory=$true)]
        $DestinationDomain
        )
    Begin {
        Write-Verbose "In Begin Block: Create-DstAzureADUser"
        $srcUserPrincipalName = $User.UserPrincipalName
        $dstUserPrincipalNameAlias = $srcUserPrincipalName -split "@" | Select-Object -First 1
        $dstUserPrincipalName = $dstUserPrincipalNameAlias + "@" + $DestinationDomain
        #Write-Verbose "In Group creation function `nDestination domain: $DestinationDomain & $dstUserPrincipalName" 
        Write-Log -message "Destination domain: $DestinationDomain & Destination UPN: $dstUserPrincipalName" -level INFO -logFile $logFile

    }    
    Process{
        Write-Verbose "Group variable value is: $ADGroups"
        
        if ($ADGroups -ne "NotPartOfAnyGroup" -or $null -ne $ADGroups)
        {
            try
            {
                Write-Log -message "Creating group at destination"
                $User = Get-AzureADUser -ObjectId $dstUserPrincipalName
                foreach ($ADGroup in $ADGroups)
                {
                    Write-Verbose "AD Group: $($ADGroup.MailNickname)"
                    $validateADGroup = Get-AzureADMSGroup -All $true | Where-Object {$_.MailNickname -eq $ADGroup.MailNickname} -ErrorAction SilentlyContinue
                    if ($null -eq $true)
                    {
                        Write-Verbose "Creating AD Group: $($ADGroup.DisplayName)" 
                        $Groupcreated = New-AzureADMSGroup -DisplayName $ADGroup.DisplayName -Description $ADGroup.Description -MailEnabled $ADGroups.MailEnabled -MailNickname $ADGroup.MailNickname -SecurityEnabled $ADGroup.SecurityEnabled -IsAssignableToRole $ADGroup.IsAssignableToRole -Visibility $ADGroup.Visibility
                        Write-Log -message "$($ADGroup.DisplayName) group has been created" -level INFO -logFile $logFile
                        Start-Sleep -Seconds 1
                        $validateADGroup = Get-AzureADMSGroup -All $true | Where-Object {$_.MailNickname -eq $ADGroup.MailNickname} -ErrorAction SilentlyContinue
                    }
                    
                    $AdduserToGroup =  Add-AzureADGroupMember -ObjectId $validateADGroup.ObjectId -RefObjectId $User.ObjectId -ErrorAction SilentlyContinue
                    Write-Log -message "$dstUserPrincipalName user has been added to $($validateADGroup.DisplayName)"
                }

                $return = "$dstUserPrincipalName user has been added to $($ADGroups.DisplayName)`n"
                <#if ($ADGroupsOwners -ne "NoOwnershipWithAnyGroup")
                    {
                        
                        foreach ($ADGroupsOwner in $ADGroupsOwners)
                        {
                            $validateADGroupOwner = Get-AzureADMSGroup -All $true | Where-Object {$_.DisplayName -eq $ADGroupsOwner.DisplayName} -ErrorAction SilentlyContinue]
                            #setting as owner
                            $SetAsOwner = Add-AzureADGroupOwner -ObjectId $validateADGroupOwner.ObjectId -RefObjectId $User.ObjectId -ErrorAction SilentlyContinue
                            Write-Log -message "$dstUserPrincipalName has been set owner to $($validateADGroupOwner.DisplayName)" -level INFO -logFile $logFile
                        }
                        $return += "$dstUserPrincipalName user set as owner to $($ADGroupsOwners.DisplayName)"
                    }#>
                
                $ReturnStatus = "Completed"
                return $return, $retuenStatus
                
            }
            catch
            {
                $return = "$dstUserPrincipalName user failed to add on Destination Tenant group $($ADGroups.DisplayName) `n"
                $return += "`nError Message: $($_.Exception.Message)"
                $return += "`nError in Line: $($_.InvocationInfo.Line)"
                $return += "`nError in Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                $return += "`nError Item Name: $($_.Exception.ItemName)"
                $ReturnStatus = "FailedOrPartiallyFailed"
                return $return, $ReturnStatus
            }
        }

        else
        {
            $Message = "User is not part of any security group at source"
            Write-Verbose $Message
            Write-Log -message $Message -level INFO -logFile $logFile
            $retuenStatus = "Completed"
            return $Message, $retuenStatus
        }
        
        
    }

}

#Function for execute
function Main
{
    Write-Log -message "Start executing" -level INFO -logFile $logFile
    if ($null -eq $UserPrincipalName)
    {
        Write-Log -message "UserPrincipalName switch is not used. Asking for input file" -level INFO -logFile $logFile
        $input = Get-FileName
        Write-Log -message "Input file name is $input" -logFile $logFile -level INFO
        if ($input -eq "Nothing")
        {
            $Message = "No input file selected"
            Write-Verbose $Message
            Write-Log -message "$Message. aborting script" -level ERROR -logFile $logFile
            $wshell = New-Object -ComObject Wscript.Shell
            $Output = $wshell.Popup("$Message",0,"Error",0+16)
            break
        }
        $users = Get-Content $input
    }
    else
    {
        Write-Log -message "UserPrincipalName switch is used" -level INFO -logFile $logFile
        $users = $UserPrincipalName
    }

    $usersCount = $users.Count
    $Message = "Total users are $usersCount."
    Write-Verbose $Message
    Write-Log -message $Message -level INFO -logFile $logFile
    
    foreach ($UserPrincipalName in $users)
    {
        $pct = "0"
        $pcti = $pcti + 1
        $pct = ($pcti/$usersCount) * 100
        $UserPrincipalName = $UserPrincipalName.Trim()
        Write-Progress -Activity "Migrating from Source Azure AD to Tergate Azure AD" -Status "Processing User $pcti of $usersCount - $UserPrincipalName" -PercentComplete $pct

        if ($null -eq $SourceTenantCreadential)
        {
            Write-Log -message "SourceTenantCreadential switch not used. Initiating credential window " -level INFO -logFile $logFile
            $SourceTenantCreadential = Get-Credential -Message "Please enter Source tenant Creadential" 
        }
        ##### Connecting Source Teant
        $Message = "Connecting Source tenant - $($SourceTenantCreadential.UserName)."
        Write-Verbose $Message
        Write-Log -message $Message -level INFO -logFile $logFile
        $connectSourceTenant = Connect-AzureAD -Credential $SourceTenantCreadential
        $validateScred = Get-AzureADUser | Select-Object -First 1 -ErrorAction SilentlyContinue
        if ($null -eq $validateScred)
        {
            $Message = "Creadential Source tenant are not authenticated - $($SourceTenantCreadential.UserName)."
            Write-Verbose "$Message"
            Write-Log -message "$Message. aborting script" -level ERROR -logFile $logFile
            $wshell = New-Object -ComObject Wscript.Shell
            $Output = $wshell.Popup("$Message",0,"Error",0+16)
            break

        }
    
        Write-Log -message "Start exporting attributes for $UserPrincipalName" -level INFO -logFile $logFile
        $MigrateUser = Get-SrcAzureADUser -UPN $UserPrincipalName
        $MigrateUserGroup = Get-SrcAzureADUserGroup -UPN $UserPrincipalName
        #$MigrateUser, $MigrateUserGroup, $MigrateUserGroupOwner = Get-SrcAzureADUser -UPN $UserPrincipalName
        Write-Verbose "Groups are: $($MigrateUserGroup.displayname -join(';') )"
        Write-Log -message "Groups are: $($MigrateUserGroup.displayname -join(';') )" -level INFO -logFile $logFile
        #####Disconnecting Source Tenat
        Write-Verbose "Disconnecting Source Tenant"
        Write-Log -message "Disconnecting Source Tenant" -level WARN -logFile $logFile
        Disconnect-AzureAD

        if ($null -eq $DestinationTenantCreadential)
        {
            Write-Log -message "DestinationTenantCreadential switch not used. Initiating credential window" -level INFO -logFile $logFile
            $DestinationTenantCreadential = Get-Credential -Message "Please enter Destination tenant Creadential" 
        }
        ##### Connecting Destination Teant
        $Message = "Connecting Source tenant - $($DestinationTenantCreadential.UserName)."
        Write-Verbose $Message
        Write-Log -message $Message -level INFO -logFile $logFile
    
        $connectDestinationTenant = Connect-AzureAD -Credential $DestinationTenantCreadential
        $validateDcred = Get-AzureADUser | Select-Object -First 1 -ErrorAction SilentlyContinue
        if ($null -eq $validateDcred)
        {
            $Message = "Creadential Destination tenant are not authenticated - $($DestinationTenantCreadential.UserName)."
            Write-Verbose "$Message"
            Write-Log -message "$Message. aborting script" -level ERROR -logFile $logFile
            $wshell = New-Object -ComObject Wscript.Shell
            $Output = $wshell.Popup("$Message",0,"Error",0+16)
            break

        }
    
        #### Generate random password
        $NewPass = Get-RandomPassword 8
        Write-Verbose "New Password is $NewPass"
        Write-Log -message "New Password is $NewPass" -level INFO -logFile $logFile
        ##### Creating user in destination tenant
        $UserCreateDateTimeStamp = (Get-Date -Format dd-MM-yyyy-HH:mm:ss).ToString()
        $newUser, $newUserStatus = Create-DstAzureADUser -DestinationDomain $DestinationDomain -NewPass $NewPass -User $MigrateUser
        $Grouptaskinfo, $GrouptaskStatus = Create-DstAzureADUserGroup -User $MigrateUser -ADGroups $MigrateUserGroup -DestinationDomain $DestinationDomain #-ADGroupsOwners $MigrateUserGroupOwner 

        ## Exporting the Status
        $UserStatusExport = [ordered]@{
            DateTimeStame = $UserCreateDateTimeStamp 
            UserPrincipalName = $UserPrincipalName
            NewPassword = $NewPass
            UserCreationStatus = $newUserStatus
            AdditionalInfo = $newUser
            SourceSecurityGroups = $MigrateUserGroup.Displayname -join ';'
            GroupTaskInfo = $Grouptaskinfo
            GroupupdateStatus = $GrouptaskStatus     
        
        }
        Write-Verbose "DateTimeStame: $UserCreateDateTimeStamp ; UserPrincipalName: $UserPrincipalName ; NewPassword: $NewPass ; Status: $newUserStatus; Info: $newUser; "
        Write-Log -message "DateTimeStame: $UserCreateDateTimeStamp ; UserPrincipalName: $UserPrincipalName ; NewPassword: $NewPass ; Status: $newUserStatus; Info: $newUser; " -level INFO -logFile $logFile
        [PSCustomObject]$UserStatusExport | Export-Csv -NoTypeInformation $OutputFilePath -Append

        #####Disconnecting Source Tenat
        Write-Verbose "Disconnecting Destination Tenant"
        Write-Log -message "Disconnecting Destination Tenant" -level WARN -logFile $logFile
        Disconnect-AzureAD
        Write-Log -message "$pct% has been completed" -level INFO -logFile $logFile
    }
}

#Global Variable
$DateTimeStamp = Get-Date -Format ddMMyyhhmm
$Path = (Get-Location).ProviderPath
$logFile = $Path + "\AzureADMigrationStatus-" + $DateTimeStamp + ".log"
$DateTimeZone = Get-TimeZone
Write-Log -message "Log DateTime format is Date/Month/Year Hour:Minute:Second" -level INFO -logFile $logFile
Write-Log -message "Time Zone is $($DateTimeZone.StandardName) - $($DateTimeZone.DisplayName)" -level INFO -logFile $logFile
$OutputFilePath = $Path + "\AzureADMigrationStatus-" + "$DateTimeStamp" + ".csv"
Write-Log -message "log file path is $logFile" -level INFO -logFile $logFile
Write-Log -message "Status for all users path is $OutputFilePath." -level INFO -logFile $logFile
[int]$pcti = "0"
 
Main

#### End of script ######