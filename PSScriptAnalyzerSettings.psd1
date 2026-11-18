@{
    # Errors and warnings fail CI. Information-level findings (trailing whitespace and the like) do not.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # These are interactive console scripts. Write-Host output for an operator is intended.
        'PSAvoidUsingWriteHost',

        # Style rule only. Get-GraphApiAllPages, Get-IntuneGraphHeaders, Get-ProxySettings and
        # Remove-ODataInjectionChars are public names that other scripts may already call.
        'PSUseSingularNouns'
    )
}
