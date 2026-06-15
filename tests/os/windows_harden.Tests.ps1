Describe "Windows hardening script contract" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot "../../windows/harden.ps1"
        $tokens = $null
        $parseErrors = $null
        $script:ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath, [ref]$tokens, [ref]$parseErrors
        )
    }

    It "parses without errors" {
        $parseErrors | Should -BeNullOrEmpty
    }

    It "defaults to Audit mode" {
        $mode = $ast.ParamBlock.Parameters | Where-Object Name -Match "Mode"
        $mode.DefaultValue.Value | Should -Be "Audit"
    }

    It "supports ShouldProcess for apply operations" {
        $ast.ParamBlock.Attributes.TypeName.FullName | Should -Contain "CmdletBinding"
        $ast.Extent.Text | Should -Match "SupportsShouldProcess"
    }
}

