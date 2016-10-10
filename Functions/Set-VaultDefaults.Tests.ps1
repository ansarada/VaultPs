$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here\$sut"

Describe "Set-VaultDefaults" {
    
    It "Sets a list servers seperated by semicolon"{  
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole'
        $env:Vault_Servers | Should Be 'vaulta.com:8200;vaultb.com:8200;vaultc.com:8200;'
    }
    
    It "Sets the Vault Role as specified"{
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole'
        $env:Vault_Role | Should Be 'testRole'
    }
    
    It "Sets AuthMethod to Ec2 by Default" {
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole'
        $env:Vault_AuthMethod | Should Be 'EC2'
    }
    
    It "Creates a Nonce variable if AuthMethod is EC2 by Default if there's no Nonce Set" {
        [Environment]::SetEnvironmentVariable("Vault_Nonce", $null, "User")
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole' -AuthMethod 'EC2'
        [environment]::GetEnvironmentVariable("Vault_Nonce","User").ToString().Length | Should Be 32
    }
    
    It "The Nonce must contain numbers and letters" {
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole' -AuthMethod 'EC2'
        [Environment]::GetEnvironmentVariable("Vault_Nonce","User").ToString() -match '[A-Za-z_0-9]' | Should Be $true
    }
    
    It "It allows username and password authentication" {
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole' -AuthMethod 'userpass' -Username 'user' -Password 'password123'
        $env:Vault_AuthMethod | Should Be 'userpass'
        $env:Vault_Username | Should Be 'user'
        $env:Vault_Password | Should Be 'password123'
    }
    
    It "Does not overwrite a Nonce variable if already set and if AuthMethod is EC2" {
        $TempNonce = 'AbCDEFGHIJKLmNOPQRSTUVWXYZ123456'
        [Environment]::SetEnvironmentVariable("Vault_Nonce", $TempNonce, "User")
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole' -AuthMethod 'EC2'
        [Environment]::GetEnvironmentVariable("Vault_Nonce","User") | Should Be $TempNonce
    }
    
    It "Sets the default port to 8200"{
        Set-VaultDefaults -Servers 'vaulta.com', 'vaultb.com', 'vaultc.com' -Role 'testRole'
        $env:Vault_Servers | Should Be 'vaulta.com:8200;vaultb.com:8200;vaultc.com:8200;'
    }
    
    It "Sets single Vault server"{
        Set-VaultDefaults -Servers 'vaulta.com' -Role 'testRole'
        $env:Vault_Servers | Should Be 'vaulta.com:8200;'
    }
    
    It "Changes default port number"{
        Set-VaultDefaults -Servers 'vaulta.com' -Role 'testRole' -VaultPort 1111
        $env:Vault_Servers | Should Be 'vaulta.com:1111;'
    }
    
    It "Throws an error if default port number is not an Int"{
        { Set-VaultDefaults -Servers 'vaulta.com' -Role 'testRole' -VaultPort 'asdf' } | Should Throw
    }
    
    It "Throws an error if no servers are specified"{
        { Set-VaultDefaults -Role 'testRole' } | Should Throw
    }
    
    It "Throws an error if no role is specified and auth method is ec2"{
        { Set-VaultDefaults -Servers 'vaulta.com' -AuthMethod 'EC2' } | Should Throw
    }
    
    It "Throws an error if no username is specified and auth method is userpass"{
        { Set-VaultDefaults -Servers 'vaulta.com' -AuthMethod 'userpass' -Password '1234' } | Should Throw
    }
    
    It "Throws an error if no password is specified and auth method is userpass"{
        { Set-VaultDefaults -Servers 'vaulta.com' -AuthMethod 'userpass' -Username 'exampleUsername' } | Should Throw
    }
    
    It "Throws an error if an invalid Auth Method is specified"{
        { Set-VaultDefaults -Servers 'vaulta.com' -Role 'testRole' -AuthMethod 'aklsdjf' } | Should Throw
    }
}