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

function Modify-Groups {
    $OU = "DC=hast,DC=interal"
}

function Create-Users {
    <#
    .DESCRIPTION
    
    #>

    # leave firstname blank because of the structure of badblood
    # First Name: 'blank'
    # Surname: 'JOHN_SMITH'
    # Domain is same across all accounts
    $FirstName =            ""
    $Domain =               $env:userdnsdomain

    # create first user that is domain admin
    # and can add members to this group
    Write-Host 
    Write-Host "======== First User Attributes ========="
    Write-Host "- Domain Admin"
    Write-Host "- Add Users to Domain Admin Group"
    Write-Host "- Can't Logon to Any Workstations"
    Write-Host 

    $Surname = Read-Host "Enter Last Name: "
    $Description = Read-Host "Enter the User's Description: "
    $FullName = "$FirstName $Surname"
    $LogonName = $FullName
    $Password = Specify-Password()

    New-ADUser `
    - Name $FullName
    - GivenName $Firstname
    - Surname $Surname
    - SamAccountName $LogonName
    - UserPrincipalName $LogonName@$Domain
    - Displayname $FullName
    - LogonWorkstations $null
    - Path 
    - AccountPassword $Password
    - Enabled $true
    - PasswordNeverExpires $true

    Write-Host "======================================="
    Write-Host
    Write-Host "Firstname:                   $Firstname"
    Write-Host "Lastname:                      $Surname"
    Write-Host "Display Name:                 $FullName"
    Write-Host "Logon Name:                  $LogonName"
    Write-Host "OU:                                 $OU"
    Write-Host "Domain:                         $Domain"
    Write-Host "Password:                     $Password"
    Write-Host "Credential - Not Expire:             No"
    Write-Host "Enabled:                            Yes"
    Write-Host "Logon Workstation/s:               NULL"
    Write-Host
}

function Main {
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

Main