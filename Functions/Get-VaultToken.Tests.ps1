$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here\$sut"
. "$here\Invoke-VaultRequest.ps1"

Describe "Get-VaultToken" {    
    
    Context "Successful EC2-Auth result tests"{
        BeforeEach{
            $clientToken = 'c9368254-3f21-aded-8a6f-7c818e81b17a'    
            $env:Vault_Role = 'testRole'
            $env:Vault_Nonce = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd123456'
            $env:Vault_AuthMethod = 'EC2'
            $body = @{
                pkcs7 = "sample policyDoc xxxxxx";
                role = $env:Vault_Role;
                nonce = $env:Vault_Nonce
            }
        }
        Mock Invoke-WebRequest { return @{content = 'sample policyDoc xxxxxx'} }
        
        #Default Mock Returned
        Mock Invoke-VaultRequest { throw 'PESTER ERROR' }
        #Passing in specific get Vault Token parameters
        Mock Invoke-VaultRequest {
            return @{ 
                content = '{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"c9368254-3f21-aded-8a6f-7c818e81b17a","accessor":"4baac95c-721a-2839-fd0b-3f06b4389776","policies":["default","devops"],"metadata":{"ami_id":"ami-ac4f6fcf","instance_id":"i-02fc228f62f8ba0ea","region":"ap-southeast-2","role":"devops","role_tag_max_ttl":"0"},"lease_duration":2592000,"renewable":true}}';
                StatusCode = 200
            }
        } -ParameterFilter { $VaultPath -eq 'v1/auth/aws-ec2/login'; $HttpMethod -eq 'Post'; $IgnoreSsl -eq $true; $HttpBody -eq $body }
    
        It 'Returns a secure string token'{
            $token = Get-VaultToken
            $token | Should BeOfType System.Security.SecureString
        }
        
        It 'Should be able to decrypt the secureString'{
            $token = Get-VaultToken
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
            $tokenPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $tokenPlainText | Should be $clientToken
        }
    }
    
    Context "Failing EC2-Auth results test"{
        BeforeEach{
            $clientToken = 'c9368254-3f21-aded-8a6f-7c818e81b17a'    
            $env:Vault_Role = 'testRole'
            $env:Vault_Nonce = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd123456'
            $env:Vault_AuthMethod = 'EC2'
            $body = @{
                pkcs7 = "sample policyDoc xxxxxx";
                role = $env:Vault_Role;
                nonce = $env:Vault_Nonce
            }
        }
        Mock Invoke-WebRequest {
            return @{content = 'sample policyDoc xxxxxx'}
        }
        It 'Throws an error if cannot get a token'{
            Mock Invoke-VaultRequest { throw 'Unable to get a healthy response: Pester Test' }
            { $token = Get-VaultToken } | Should throw 'Could not get Vault Auth token'
        }
        
        It 'Throws an error if Invoke-VaultRequest returns null'{
            Mock Invoke-WebRequest { return @{content = 'sample policyDoc xxxxxx'} } -ParameterFilter { $uri -eq 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7' }
            Mock Invoke-VaultRequest { return $null }
            { $token = Get-VaultToken } | Should throw 'No result returned'
        }
        
        It 'Throws an error if get pkcs7 throws an error'{
            Mock Invoke-WebRequest { throw 'Pester Error' } -ParameterFilter { $uri -eq 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7' }
            { $token = Get-VaultToken } | Should throw 'Could not get instance policy document'
        }
        
        It 'Throws an error if get pkcs7 returns null'{
            Mock Invoke-WebRequest { return $null } -ParameterFilter { $uri -eq 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7' }
            { $token = Get-VaultToken } | Should throw 'Could not get instance policy document'
        }
        
        It 'Attempt to get the pkcs7 policy doc 3 times'{
            Mock Invoke-WebRequest { return $null } -ParameterFilter { $uri -eq 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7' }
            { $token = Get-VaultToken } | Should throw 'Could not get instance policy document'
            Assert-MockCalled Invoke-WebRequest -Exactly 3 -Scope It
        }
        
        It 'Will try to get policy document a second time if the first time fails'{
            $Env:i = 0
            Mock Invoke-WebRequest -MockWith {
                $i = [convert]::ToInt32($Env:i, 10) + 1
                $Env:i = $i
                if($i -eq 2){
                    return @{content = 'sample policyDoc xxxxxx'}
                } else{
                    throw 'Error!'
                }
            } -ParameterFilter { $uri -eq 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7' }
            Mock Invoke-VaultRequest { 
                return @{ 
                    content = '{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"c9368254-3f21-aded-8a6f-7c818e81b17a","accessor":"4baac95c-721a-2839-fd0b-3f06b4389776","policies":["default","devops"],"metadata":{"ami_id":"ami-ac4f6fcf","instance_id":"i-02fc228f62f8ba0ea","region":"ap-southeast-2","role":"devops","role_tag_max_ttl":"0"},"lease_duration":2592000,"renewable":true}}';
                    StatusCode = 200
                }
            }
            $token = Get-VaultToken
            Assert-MockCalled Invoke-WebRequest -Exactly 2 -Scope It
        }
    }
    
    Context "Successful UserPass result tests"{
        BeforeEach{
            $clientToken = 'c9368254-3f21-aded-8a6f-7c818e81b17a'    
            $env:Vault_AuthMethod = 'userpass'
            $env:Vault_Username = 'user'
            $env:Vault_Password = 'password'
            $body = @{
                password = 'password';
            }
        }
        #Default Mock Returned
        Mock Invoke-VaultRequest { throw 'PESTER ERROR' }
        #Passing in specific get Vault Token parameters
        Mock Invoke-VaultRequest {
            return @{ 
                content = '{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"c9368254-3f21-aded-8a6f-7c818e81b17a","accessor":"4baac95c-721a-2839-fd0b-3f06b4389776","policies":["default","devops"],"metadata":{"ami_id":"ami-ac4f6fcf","instance_id":"i-02fc228f62f8ba0ea","region":"ap-southeast-2","role":"devops","role_tag_max_ttl":"0"},"lease_duration":2592000,"renewable":true}}';
                StatusCode = 200
            }
        } -ParameterFilter { $VaultPath -eq 'v1/auth/userpass/login/user'; $HttpMethod -eq 'Post'; $IgnoreSsl -eq $true; $HttpBody -eq $body }
        
        It 'Userpass returns a secure string token'{
            $token = Get-VaultToken
            $token | Should BeOfType System.Security.SecureString
        }
        
        It 'userpass should be able to decrypt the secureString'{
            $token = Get-VaultToken
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
            $tokenPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $tokenPlainText | Should be $clientToken
        }
    }
}