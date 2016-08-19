$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here\$sut"
. "$here\Invoke-VaultRequest.ps1"

Describe "Get-VaultSecret" {
    
    BeforeEach{
        $clientToken = 'c9368254-3f21-aded-8a6f-7c818e81b17a'
        $env:Vault_Servers = 'ansaradatest:443;'        
        $vaultRequestPath = 'v1/testpath/hello'
        $vaultSecureToken = ConvertTo-SecureString $clientToken -AsPlainText -Force
    }
    
    Context "Successful result tests"{
        BeforeEach{
            Mock Invoke-VaultRequest { 
                return @{ 
                    Content = '{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"2e41df2f-18b0-2bfc-b820-597ffb7f4030","accessor":"4baac95c-721a-2839-fd0b-3f06b4389776","policies":["default","devops"],"metadata":{"ami_id":"ami-ac4f6fcf","instance_id":"i-02fc228f62f8ba0ea","region":"ap-southeast-2","role":"devops","role_tag_max_ttl":"0"},"lease_duration":2592000,"renewable":true}}';
                    StatusCode = '200'
                }
            } -ParameterFilter { $VaultPath -eq 'v1/testpath/hello'; $HttpMethod -eq 'Get'; $HttpHeaders -eq @{ 'X-Vault-Token' = "${clientToken}"} }
        }

        It "Will send a request with vault path"{
            $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken
            Assert-MockCalled Invoke-VaultRequest -Exactly 1 -ParameterFilter { $VaultPath -eq $vaultRequestPath }  -Scope It
        }

        It "Will send a GET request"{
            $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken
            Assert-MockCalled Invoke-VaultRequest -Exactly 1 -ParameterFilter { $HttpMethod -eq 'Get'}  -Scope It
        }
        
        It "Will send a request with the Vault Token"{
            $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken
            Assert-MockCalled Invoke-VaultRequest -Exactly 1 -ParameterFilter { $HttpHeaders['X-Vault-Token'] -eq "${clientToken}" } -Scope It
        }

        It "Will send a request and send a parameter to ignore SSL"{
            $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken -IgnoreSsl $true
            Assert-MockCalled Invoke-VaultRequest -Exactly 1 -ParameterFilter { $IgnoreSsl -eq $true } -Scope It
        }
    }

    Context "Failed tests"{
        It "Will throw an error if return code is not 200"{
            Mock Invoke-VaultRequest { 
                return @{ 
                    Content = '{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,"auth":{"client_token":"2e41df2f-18b0-2bfc-b820-597ffb7f4030","accessor":"4baac95c-721a-2839-fd0b-3f06b4389776","policies":["default","devops"],"metadata":{"ami_id":"ami-ac4f6fcf","instance_id":"i-02fc228f62f8ba0ea","region":"ap-southeast-2","role":"devops","role_tag_max_ttl":"0"},"lease_duration":2592000,"renewable":true}}';
                    StatusCode = 400
                }
            }
            
            { $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken } | Should Throw "HTTP Status Code was not 200"
        }

        It "Will throw an error if content is empty"{
            Mock Invoke-VaultRequest { 
                return @{ 
                    Content = @{};
                    StatusCode = '200'
                }
            }
            
            { $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken } | Should Throw "unable to return a set of result"
        }

        It "Will throw an error if there is no content at all"{
            Mock Invoke-VaultRequest { 
                return @{                     
                    StatusCode = '200'
                }
            }
            
            { $result = Get-VaultSecret -VaultPath $vaultRequestPath -VaultToken $vaultSecureToken } | Should Throw "unable to return a set of result"
        }
    }

    Context "No required values tests"{
        BeforeEach{
            Mock Invoke-VaultRequest
        }

        It "No VaultPath provided should throw an error"{
            { $result = Get-VaultSecret -VaultToken $vaultSecureToken } | Should throw "VaultPath is mandatory"            
        }

        It "Sending a non secure string for VaultToken should throw an error"{
            { $result = Get-VaultSecret -VaultToken '123ds' } | Should throw "`"System.String`" to type `"System.Security.SecureString`""
        }

        It "No VaultToken provided should throw an error"{
            { $result = Get-VaultSecret -VaultPath $vaultRequestPath } | Should throw "VaultToken is mandatory"            
        }
    }   
}