<#
.SYNOPSIS
A script to insert honey users into the generated AD Badblood Environment, provided as part of dissertation work. 

.DESCRIPTION
Created using PowerShell, the script inserts 4 honey users using set variables.

Author: Ethan Hastie
#>

Import-Module ActiveDirectory

function Show-Menu {
    <#
    .DESCRIPTION
    Created using PowerShell, provides an interactive main menu.
    #>

    Clear-Host
    Write-Host "============ HoneyAD ==============="
    Write-Host 
    Write-Host "1: Press '1' to create the users."
    Write-Host "2: Press '2' for description."
    Write-Host "Q: Press 'Q' to quit."
    Write-Host
}

function Specify-Password {
    <#
    .DESCRIPTION
    Create a password for the user according to length and complexity requirements
    
    Original Link to Password Creation:
        author:
            Paul (The SYSADMIN Channel)
        link: 
            https://thesysadminchannel.com/script-create-user-accounts-in-powershell/
    #>

    # TOGGLE ME if password policy different
    $PasswordLength =         7

    do {

        Write-Host
            $isGood = 0
            $Password = Read-Host "Enter the Password " -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $Complexity = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

            # as long as password meets 3 basic requirements and satisfies length requirements
            if ($Complexity.Length -ge $PasswordLength) {
                Write-Host
            } else {
                Write-Host "Password needs $PasswordLength or more Characters" -ForegroundColor:Green
            }
        
            if ($Complexity -match "[^a-zA-Z0-9]") {
                $isGood++
            } else {
                Write-Host "Password does not contain Special Characters." -ForegroundColor:Green
            }
        
            if ($Complexity -match "[0-9]") {
                $isGood++
            } else {
                Write-Host "Password does not contain Numbers." -ForegroundColor:Green
            }
        
            if ($Complexity -cmatch "[a-z]") {
                $isGood++
            } else {
                Write-Host "Password does not contain Lowercase letters." -ForegroundColor:Green
            }
        
            if ($Complexity -cmatch "[A-Z]") {
                $isGood++
            } else {
                Write-Host "Password does not contain Uppercase letters." -ForegroundColor:Green
            }
    } until ($Password.Length -ge $PasswordLength -and $isGood -ge 3)

    return $Password
}

function Create-Users {
    <#
    .DESCRIPTION
    Creates the honey users.
    #>

    # TOGGLE ME 
    $OU =                   "DC=hast,DC=interal"
    $Domain = $env:userdnsdomain

    ##############################################################################

    # create first user that is domain admin
    Write-Host 
    Write-Host "======== First User Attributes ========="
    Write-Host "- Domain Admin"
    Write-Host "- Can't Logon to Any Workstations (Set Manually)"
    Write-Host "- AS-REP Roastable"
    Write-Host "- Password Never Expires"
    Write-Host 

    $answer1 = Read-Host "Would you like to create this user (Y/N) "

    if ($answer1 -eq "Y" -Or $answer1 -eq "y") {
        $FirstName = Read-Host "Enter First Name "
        $Surname = Read-Host "Enter Last Name "
        $Description = "Created with secframe.com/badblood."
        $FullName = $FirstName + "_" + $Surname

        # set capitalised to conform to naming conventions
        $FullName = $FullName.ToUpper()
        $LogonName = $FullName
        $Password = Specify-Password
        $CombinedOU = "OU=Tier 0,OU=Admin,"+$OU
        
        # create the user
        New-ADUser -Name $FullName -Surname $FullName -Description $Description -SamAccountName $LogonName -UserPrincipalName $LogonName@$Domain -DisplayName $FullName -Path $CombinedOU -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true

        # Make vulnerable to AS-REP Roasting by turning off
        # require kerberos pre-authentication
        Get-ADUser -Identity $FullName | Set-ADAccountControl -doesnotrequirepreauth $true

        # Copy group membership from user in Domain Admin Group to created user
        $GetGroups = Get-ADUser -Identity JACKLYN_GONZALEZ -Properties memberof | Select-Object -ExpandProperty memberof
        $GetGroups | Add-ADGroupMember -Members $FullName

        Write-Host "======================================="
        Write-Host
        Write-Host "Firstname:                   $Firstname"
        Write-Host "Lastname:                    $Surname"
        Write-Host "Display Name:                $FullName"
        Write-Host "Logon Name:                  $LogonName"
        Write-Host "OU:                          $CombinedOU"
        Write-Host "Domain:                      $Domain"
        Write-Host "Credential - Not Expire:     Yes"
        Write-Host "Pre-Authentication:          No"
        Write-Host "Enabled:                     Yes"

        # Set Auditing and Deny Logon using GUI
        Write-Host "Auditing:                    (Set Manually)"
        Write-Host "Deny Logon:                  (Set Manually)"
        Write-Host

        # display properties of the created user
        Write-Host "Account Created:"
        Get-ADUser -Identity $FullName
        Write-Host
    }

    ##############################################################################

    # create second user that is administrator
    Write-Host 
    Write-Host "======== Second User Attributes ========="
    Write-Host "- Administrator"
    Write-Host "- Can't Logon to Any Workstations (Set Manually)"
    Write-Host "- AS-REP Roastable"
    Write-Host "- Password Never Expires"
    Write-Host 

    $answer2 = Read-Host "Would you like to create this user (Y/N) "

    if ($answer2 -eq "Y" -Or $answer2 -eq "y") {
        $FirstName = Read-Host "Enter First Name "
        $Surname = Read-Host "Enter Last Name "
        $Description = "Created with secframe.com/badblood."
        $FullName = $FirstName + "_" + $Surname
        $FullName = $FullName.ToUpper()
        $LogonName = $FullName
        $Password = Specify-Password
        $CombinedOU = "OU=Tier 1,OU=Admin,"+$OU

        # create user, as-rep vulnerable and copy group privileges from member in Administrators group
        New-ADUser -Name $FullName -Surname $FullName -Description $Description -SamAccountName $LogonName -UserPrincipalName $LogonName@$Domain -DisplayName $FullName -Path $CombinedOU -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true
        Get-ADUser -Identity $FullName | Set-ADAccountControl -doesnotrequirepreauth $true
        $GetGroups = Get-ADUser -Identity HOUSTON_LOWERY -Properties memberof | Select-Object -ExpandProperty memberof
        $GetGroups | Add-ADGroupMember -Members $FullName
        
        Write-Host "======================================="
        Write-Host
        Write-Host "Firstname:                   $Firstname"
        Write-Host "Lastname:                    $Surname"
        Write-Host "Display Name:                $FullName"
        Write-Host "Logon Name:                  $LogonName"
        Write-Host "OU:                          $CombinedOU"
        Write-Host "Domain:                      $Domain"
        Write-Host "Credential - Not Expire:     Yes"
        Write-Host "Pre-Authentication:          No"
        Write-Host "Enabled:                     Yes"
        Write-Host "Auditing:                    (Set Manually)"
        Write-Host "Deny Logon:                  (Set Manually)"
        Write-Host

        Write-Host "Account Created:"
        Get-ADUser -Identity $FullName
        Write-Host
    }

    ##############################################################################

    # create third user who has interesting attack path to Domain Controllers group
    Write-Host 
    Write-Host "======== Third User Attributes ========="
    Write-Host "- Local User"
    Write-Host "- Can't Logon to Any Workstations (Set Manually)"
    Write-Host "- Password Never Expires"
    write-Host "- Password in Description (Set Manually)"
    Write-Host "- Has Rights to User in Domain Controllers Group, Domain and GP Creator Owners"
    Write-Host 

    $answer3 = Read-Host "Would you like to create this user (Y/N) "

    if ($answer3 -eq "Y" -Or $answer3 -eq "y") {
        $FirstName = Read-Host "Enter First Name "
        $Surname = Read-Host "Enter Last Name "
        $FullName = $FirstName + "_" + $Surname
        $FullName = $FullName.ToUpper()
        $LogonName = $FullName
        $Password = Specify-Password

        # add password into desc via GUI
        $Description = "Just so I don't forget my password is"
        $CombinedOU = "OU=Test,OU=BDE,OU=Stage,"+$OU

        New-ADUser -Name $FullName -Surname $FullName -Description $Description -SamAccountName $LogonName -UserPrincipalName $LogonName@$Domain -DisplayName $FullName -Path $CombinedOU -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true
        $GetGroups = Get-ADUser -Identity SUSANNA_CAMPOS -Properties memberof | Select-Object -ExpandProperty memberof
        $GetGroups | Add-ADGroupMember -Members $FullName

        Write-Host "======================================="
        Write-Host
        Write-Host "Firstname:                   $Firstname"
        Write-Host "Lastname:                    $Surname"
        Write-Host "Display Name:                $FullName"
        Write-Host "Logon Name:                  $LogonName"
        Write-Host "OU:                          $CombinedOU"
        Write-Host "Domain:                      $Domain"
        Write-Host "Credential - Not Expire:     Yes"
        Write-Host "Pre-Authentication:          Yes"
        Write-Host "Enabled:                     Yes"
        Write-Host "Auditing:                    (Set Manually)"
        Write-Host "Deny Logon:                  (Set Manually)"
        Write-Host

        Write-Host "Account Created:"
        Get-ADUser -Identity $FullName
        Write-Host
    }

    ##############################################################################

    # create fourth user who is an Account Operator with Fake Password in Description
    Write-Host 
    Write-Host "======== Fourth User Attributes ========="
    Write-Host "- Account Operator"
    Write-Host "- Fake Password in Description"
    Write-Host "- Can Logon"

    $answer4 = Read-Host "Would you like to create this user (Y/N) "

    if ($answer4 -eq "Y" -Or $answer4 -eq "y") {
        $FirstName = Read-Host "Enter First Name "
        $Surname = Read-Host "Enter Last Name "
        $FullName = $FirstName + "_" + $Surname
        $FullName = $FullName.ToUpper()
        $LogonName = $FullName
        $Password = Specify-Password
        $CombinedOU = "OU=AWS,OU=Tier 1,"+$OU

        # not real password
        $Description = "Just so I don't forget my password is c7y=emJWEQFMe"

        # create user and add to Account Operator by copying group privileges from other user
        New-ADUser -Name $FullName -Surname $FullName -Description $Description -SamAccountName $LogonName -UserPrincipalName $LogonName@$Domain -DisplayName $FullName -Path $CombinedOU -AccountPassword $Password -Enabled $true
        $GetGroups = Get-ADUser -Identity BRANDEN_SALAS -Properties memberof | Select-Object -ExpandProperty memberof
        $GetGroups | Add-ADGroupMember -Members $FullName

        Write-Host "======================================="
        Write-Host
        Write-Host "Firstname:                   $Firstname"
        Write-Host "Lastname:                    $Surname"
        Write-Host "Display Name:                $FullName"
        Write-Host "Logon Name:                  $LogonName"
        Write-Host "OU:                          $CombinedOU"
        Write-Host "Domain:                      $Domain"
        Write-Host "Credential - Not Expire:     Yes"
        Write-Host "Pre-Authentication:          Yes"
        Write-Host "Enabled:                     Yes"
        Write-Host "Auditing:                    (Set Manually)"
        Write-Host

        Write-Host "Account Created:"
        Get-ADUser -Identity $FullName
        Write-Host
    }
}

function Choose-Option {
    <#
    .DESCRIPTION
    An interactive menu to the script.    
    #>

    do {
        Show-Menu
        $option = Read-Host "Choose an option."
        switch ($option)
        {
            '1' {
                Create-Users
            } '2' {
                Write-Host 'Author: E. Hastie'
                Write-Host 'Description: a script to insert honey users into an AD Badblood environment.'
            }
        }
        pause
    }
    until ($option -eq 'q' -Or $option -eq 'Q')
}

Choose-Option
