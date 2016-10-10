Set-StrictMode -Version Latest

function Set-VaultDefaults {
<#
.SYNOPSIS
Sets the default environment variables used to communicate with Vault

.PARAMETER Servers
A list of Vault servers to loop through in other Vault methods

.PARAMETER AuthMethod
The authentication method used to communicate with Vault.
Only valid value at this time is EC2

.PARAMETER Port
The port number Vault is listening on. Default is 8200

.EXAMPLE
Set-VaultDefaults -Servers ['vaultexample-a.com', 'vaultexample-b.com']
#>
    
    param (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Servers=$(throw "Servers is mandatory, please provide a value"),

        [parameter(mandatory=$false)]
        [ValidateSet("EC2", "userpass")] 
        [String]
        $AuthMethod = 'EC2',
        
        [parameter(mandatory=$false)]
        [Int]
        $VaultPort = 8200,
        
        [parameter(mandatory=$false)]
        [String]
        $Role = '',
        
        [parameter(mandatory=$false)]
        [String]
        $Username = '',
        
        [parameter(mandatory=$false)]
        [String]
        $Password = ''
    )

    process {
        $env:Vault_Servers = $null
        foreach ($server in $servers){
            $env:Vault_Servers += "${server}:${VaultPort};"
        }
        $env:Vault_AuthMethod = $AuthMethod
        
        #This is used by EC2 auth method to ensure that if in the event the pkcs7 document is compramised, only the server will know a random generated key
        #Vault will store the instance id; ami id; and this unique key (called a nonce) in it's system so even if the ec2 policy document is compromised, vault will only let the instance login
        #This will generate a random 32 character string to store this 'nonce'
        #For more info on EC2 Auth on Vault by Hashicorp, refer to: https://www.vaultproject.io/docs/auth/aws-ec2.html
        if($AuthMethod -eq 'EC2'){
            if ($Role -eq ''){
                throw "Role is mandatory is auth method if EC2, please provide a value"
            }
            $env:Vault_Role = $Role
            $Vault_Nonce = [environment]::GetEnvironmentVariable("Vault_Nonce","User")
            if ( $Vault_Nonce -eq $null -or $Vault_Nonce.ToString().length -ne 32) {
                #The next line generates a random 32 character string with upper and lower case.
                $Vault_Nonce = -join ( (65..90) + (97..122) | Get-Random -Count 32 | foreach { [char]$_ } )
                [Environment]::SetEnvironmentVariable("Vault_Nonce", $Vault_Nonce, "User")
            }
        }
        
        if($AuthMethod -eq 'userpass'){
            if ($Username -eq ''){
                throw "username is mandatory if auth method is userpass, please provide a value"
            }
            if ($Password -eq ''){
                throw "Password is mandatory if auth method is userpass, please provide a value"
            }
            $env:Vault_Username = $Username
            $env:Vault_Password = $Password
        }
    }
}
