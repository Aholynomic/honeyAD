<#
.SYNOPSIS
A script to insert honey users into the generated AD Badblood Environment, provided as part of dissertation work. 

.DESCRIPTION
Created using PowerShell, the script inserts 5 honey users using set variables.

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

    # TOGGLE ME - the minimum length is 7 chars
    $PasswordLength =         7

    do {

        Write-Host
            $isGood = 0
            $Password = Read-Host "Enter the Password: " -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $Complexity = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
 
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
    Creates the honey users and asks for several key information to create them.    
    #>

    $Domain =               $env:userdnsdomain
    $OU =                "DC=hast,DC=interal"

    ##############################################################################

    # create first user that is domain admin
    Write-Host 
    Write-Host "======== First User Attributes ========="
    Write-Host "- Domain Admin"
    Write-Host "- Can't Logon to Any Workstations"
    Write-Host "- AS-REP Roastable"
    Write-Host "- Password Never Expires"
    Write-Host 

    $FirstName = Read-Host "Enter First Name: "
    $Surname = Read-Host "Enter Last Name: "
    $Description = Read-Host "Enter the User's Description: "
    $FullName = $FirstName + "_" + $Surname
    $FullName = $FullName.ToUpper()
    $LogonName = $FullName
    $Password = Specify-Password
    $CombinedOU = $OU
    
    New-ADUser `
    - Name $FullName,
    - GivenName $Firstname,
    - Surname $Surname,
    - SamAccountName $LogonName,
    - UserPrincipalName $LogonName@$Domain,
    - DisplayName $FullName,
    - Path $OU,
    - AccountPassword $Password,
    - Enabled $true,
    - PasswordNeverExpires $true

    # Make vulnerable to AS-REP Roasting by turning off
    # require kerberos pre-authentication
    Get-ADUser -Identity $FullName | Set-ADAccountControl -doesnotrequirepreauth $true

    Write-Host "======================================="
    Write-Host
    Write-Host "Firstname:                   $Firstname"
    Write-Host "Lastname:                      $Surname"
    Write-Host "Display Name:                 $FullName"
    Write-Host "Logon Name:                  $LogonName"
    Write-Host "OU:                                 $OU"
    Write-Host "Domain:                         $Domain"
    Write-Host "Password:                     $Password"
    Write-Host "Credential - Not Expire:            Yes"
    Write-Host "Pre-Authentication:                  No"
    Write-Host "Enabled:                            Yes"
    # Set Auditing using GUI
    Write-Host "Auditing:                (Set Manually)"
    # Set Deny Logon using GUI
    Write-Host "Deny Logon:              (Set Manually)"
    Write-Host

    ##############################################################################

    # create second user that is administrator
    Write-Host 
    Write-Host "======== Second User Attributes ========="
    Write-Host "- Administrator"
    Write-Host "- Can't Logon to Any Workstations"
    Write-Host "- AS-REP Roastable"
    Write-Host "- Password Never Expires"
    Write-Host 

    $FirstName = Read-Host "Enter First Name: "
    $Surname = Read-Host "Enter Last Name: "
    $Description = Read-Host "Enter the User's Description: "
    $FullName = $FirstName + "_" + $Surname
    $FullName = $FullName.ToUpper()
    $LogonName = $FullName
    $Password = Specify-Password
    $CombinedOU = $OU

    New-ADUser `
    - Name $FullName,
    - GivenName $Firstname,
    - Surname $Surname,
    - SamAccountName $LogonName,
    - UserPrincipalName $LogonName@$Domain,
    - DisplayName $FullName,
    - Path $CombiendOU,
    - AccountPassword $Password,
    - Enabled $true,
    - PasswordNeverExpires $true

    Get-ADUser -Identity $FullName | Set-ADAccountControl -doesnotrequirepreauth $true

    Write-Host "======================================="
    Write-Host
    Write-Host "Firstname:                   $Firstname"
    Write-Host "Lastname:                      $Surname"
    Write-Host "Display Name:                 $FullName"
    Write-Host "Logon Name:                  $LogonName"
    Write-Host "OU:                                 "
    Write-Host "Domain:                         $Domain"
    Write-Host "Password:                     $Password"
    Write-Host "Credential - Not Expire:             "
    Write-Host "Pre-Authentication:                  "
    Write-Host "Enabled:                            Yes"
    Write-Host "Auditing:                (Set Manually)"
    Write-Host "Deny Logon:              (Set Manually)"
    Write-Host

    ##############################################################################

    # create third user who is fake Administrator (built-in account)
    Write-Host 
    Write-Host "======== Third User Attributes ========="
    Write-Host "Domain Admin who is Fake Administrator"
    Write-Host 

    # have here grabbing the Administrator account and manipulate it
    Write-Host "Changing Built-In Administator Details"
    $FirstName = Read-Host "Enter First Name: "
    $Surname = Read-Host "Enter Last Name: "
    $FullName = $FirstName + "_" + $Surname
    $FullName = $FullName.ToUpper()
    
    Set-ADUser Administrator -Surname $FullName -DisplayName $FullName -Description ""
    

    Write-Host "Create Fake Administrator in Place of Current Built-In Administrator"
    Write-Host 

    $Description = "Built-in account for administering the computer/domain."
    $FullName = "Administrator"
    $LogonName = $FullName
    $Password = Specify-Password
    $CombinedOU = "CN=Users,"+$OU
    
    New-ADUser `
    - Name $FullName,
    - SamAccountName $LogonName,
    - UserPrincipalName $LogonName@$Domain,
    - DisplayName $FullName,
    - Path $CombinedOU,
    - AccountPassword $Password,
    - Enabled $true,
    - PasswordNeverExpires $true

    Write-Host "======================================="
    Write-Host
    Write-Host "Display Name:                 $FullName"
    Write-Host "Logon Name:                  $LogonName"
    Write-Host "OU:                                 $OU"
    Write-Host "Domain:                         $Domain"
    Write-Host "Password:                     $Password"
    Write-Host "Credential - Not Expire:             No"
    Write-Host "Pre-Authentication:                  No"
    Write-Host "Enabled:                            Yes"
    Write-Host "Auditing:                (Set Manually)"
    Write-Host "Deny Logon:              "
    Write-Host

    ##############################################################################

    ##############################################################################
}

function Choose-Option {
    do {
        Show-Menu
        $option = Read-Host "Choose an option."
        switch ($option)
        {
            '1' {
                Write-Host "test"
            } '2' {
                Write-Host 'Author: E. Hastie'
                Write-Host 'A script to insert honey users into AD Badblood environment'
            }
        }
        pause
    }
    until ($option -eq 'q')
}

Choose-Option