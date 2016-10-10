$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
. "$here\$sut"

Describe "Invoke-VaultRequest" {
    
    Mock Ignore-SelfSignedCerts
    $env:Vault_AuthMethod = 'EC2'
    $env:Vault_Role = 'DevOps1'
    $vaultUriPath = 'test'
    $CustomPesterSuccessCode = '200'
    
    Context "Testing Get Requets"{
        $env:Vault_Servers = "ansaradatest.com:443;"
        $requestMethod = 'Get'
                
        It 'Will make GET calls'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $method -eq $requestMethod }
            $result = Invoke-VaultRequest -VaultPath $vaultUriPath -HttpMethod $requestMethod
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $method -eq $requestMethod } -Scope It
        }
        
        It 'GET uri is formed properly'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $uri -eq "https://ansaradatest.com:443/${vaultUriPath}" }
            $result = Invoke-VaultRequest -VaultPath $vaultUriPath -HttpMethod $requestMethod
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $uri -eq "https://ansaradatest.com:443/${vaultUriPath}" } -Scope It
        }
        
        It 'Will accept VaultPath starting with /'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $uri -eq "https://ansaradatest.com:443/${vaultUriPath}" }
            $result = Invoke-VaultRequest -VaultPath "/$vaultUriPath" -HttpMethod $requestMethod
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $uri -eq "https://ansaradatest.com:443/${vaultUriPath}" } -Scope It
        }
    }
    
    Context "Testing POST Requests"{
        $env:Vault_Servers = "ansaradatest.com:443;"
        $requestMethod = 'Post'
        $httpHeaders = @{testheader = 'value'}
        $httpBody= @{testbody = 'value'}
        
        It 'Will make POST calls'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $method -eq $requestMethod }
            $result = Invoke-VaultRequest -VaultPath $vaultUriPath -HttpMethod $requestMethod
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $method -eq $requestMethod } -Scope It
        }
        
        It 'Will send headers'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $method -eq $requestMethod; $Headers -eq $httpHeaders }
            $result = Invoke-VaultRequest -VaultPath 'headers' -HttpHeaders $httpHeaders -HttpMethod $requestMethod
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $Method -eq $requestMethod; $Headers -eq $httpHeaders } -Scope It
        }
        
        It 'Will send http body'{
            Mock Invoke-WebRequest { return @{ StatusCode = $CustomPesterSuccessCode } } -ParameterFilter { $method -eq $requestMethod; $body -eq $httpBody }
            $result = Invoke-VaultRequest -VaultPath 'post' -HttpBody $httpBody -HttpMethod 'Post'
            Assert-MockCalled Invoke-WebRequest -Exactly 1 -ParameterFilter { $method -eq $requestMethod; $body -eq $httpBody } -Scope It
        }
    }
    
    It 'Will try to set to system to ignore SSL errors'{
        $env:Vault_Servers = "ansaradatest.com:443;"
        Mock Invoke-WebRequest { return 'HTTP Response' }
        $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get' -IgnoreSSL $true
        Assert-MockCalled Ignore-SelfSignedCerts -Times 1
    }
    
    It 'Will attempt to Invoke WebRequest'{
        $env:Vault_Servers = "ansaradatest.com:443;"
        Mock Invoke-WebRequest { return 'HTTP Response' }
        $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get' -IgnoreSSL $true
        Assert-MockCalled Invoke-WebRequest -Exactly 1 -Scope It
    }
    
    It 'Will throw if Invoke-WebRequest response throws an error'{
        Mock Invoke-WebRequest { throw 'HTTP Error' }
        { $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get' } | Should Throw 'HTTP Error'
    }
    
    It 'Will throw if Invoke-WebRequest response returns null'{
        $env:Vault_Servers = "ansaradatest.com:443;"
        Mock Invoke-WebRequest { return $null }
        { $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get' } | Should Throw
    }
    
    It 'Will attempt to Invoke WebRequest 3 times if 3 Vault servers are defined and each time a request throws'{
        $env:Vault_Servers = "999.0.0.1:443;998.0.0.1:443;success.com:443;"
        Mock Invoke-WebRequest -MockWith {
            if ($uri -eq 'https://success.com:443/test'){
                return 'Success!'
            } else {
                throw 'HTTP Error'
            }
        }
        $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get'
        Assert-MockCalled Invoke-WebRequest -Exactly 3 -Scope It
    }
    
    It 'Will attempt to Invoke WebRequest 2 times if 3 Vault servers are defined and the 2nd time was successful'{
        $env:Vault_Servers = "999.0.0.1:443;success.com:443;998.0.0.1:443";
        Mock Invoke-WebRequest -MockWith {
            if ($uri -eq 'https://success.com:443/test'){
                return 'Success!'
            } else {
                throw 'HTTP Error'
            }
        }
        $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get'
        Assert-MockCalled Invoke-WebRequest -Exactly 2 -Scope It
    }
    
    It 'Will throw an error if all 3 servers throw an error'{
        $env:Vault_Servers = "999.0.0.1:443;success.com:443;998.0.0.1:443";
        Mock Invoke-WebRequest { throw 'HTTP ERROR' }
        { $result = Invoke-VaultRequest -VaultPath 'test' -HttpMethod 'Get' } | Should Throw "HTTP ERROR"
        
    }
    
    It 'Throw an error if no vault path is specified'{
        { Invoke-VaultRequest -HttpMethod 'Post' } | Should throw 'VaultPath is mandatory'
    }
    
    It 'Throw an error if no http method is specified'{
        { Invoke-VaultRequest -VaultPath 'v123' } | Should throw 'HttpMethod is mandatory'
    }
}