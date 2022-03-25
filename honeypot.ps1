<#
Script created by E. Hastie to automate insertion of 
honey users in powershell
#>

Import-Module ActiveDirectory -EA Stop

function Show-Menu {
    Clear-Host
    Write-Host "============ HoneyAD ==============="
    Write-Host 
    Write-Host "1: Press '1' to create user."
    Write-Host "2: Press '2' for description."
    Write-Host "Q: Press 'Q' to quit."
    Write-Host
}

function Modify-Groups {
    $OU = "DC=hast,DC=interal"
}

function Create-User {
    
    # leave firstname blank because of the structure of badblood
    # First Name: 'blank'
    # Surname: 'JOHN_SMITH'
    $FirstName = ""
    $Surname = Read-Host "Enter Last Name"
    $FullName = "$FirstName $Surname"
    $LogonName = $FullName
    $Password = Read-Host "Enter a Password" | ConvertTo-SecureString -AsPlainText -Force
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