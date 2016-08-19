try{

	$pesterPath = '.\Pester'
	Write-Host "Checking to see if Pester path ($pesterPath) exists"
	if (Test-Path $pesterPath) {
		$currentPath = Get-Location
		Write-Host "Pester path ($pesterPath) exists, saved current location ($currentPath)"
		Write-Host "Changing location to $pesterPath"
		Set-Location $pesterPath
		Write-Host "Running git pull"
		& 'git.exe' pull
		Write-Host "Reseting location to $currentPath"
		Set-Location $currentPath
	}
	else {
		Write-Host "Pester does not exist, cloning"
		& 'git.exe' clone 'https://github.com/pester/Pester.git'
	}

	Write-Host "Importing Pester module"
	Import-Module $pesterPath -Force

	$testResultPath = '.\test-reports\'

	if (Test-Path $testResultPath) {
		Write-Host "Test results path ($testResultPath) exists"
	}
	else {
		Write-Host "Test results path ($testResultPath) does not exist, creating"
		New-Item -Type directory $testResultPath | Out-Null
	}

	Write-Host "Running Pester"
	Invoke-Pester Functions -OutputFile $(Join-Path $testResultPath 'TestResults.xml') -OutputFormat 'NUnitXml'
}
catch {
	Write-Error $_
	exit -1
}