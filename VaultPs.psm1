$moduleRoot = Split-Path -Path $MyInvocation.MyCommand.Path

"$moduleRoot\Functions\*.ps1" |
	Resolve-Path |
	Where-Object { -not ($_.ProviderPath.Contains(".Tests.")) } |
	ForEach-Object {
		. $_.ProviderPath
		Export-ModuleMember $(Split-Path -Leaf $_.ProviderPath).Replace('.ps1', '')
	}
