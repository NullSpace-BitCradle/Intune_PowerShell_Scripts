@{
    # Errors and warnings fail CI. Information-level findings (trailing whitespace and the like) do not.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # These are interactive console scripts. Write-Host output for an operator is intended.
        'PSAvoidUsingWriteHost',

        # Style rule only. Get-GraphApiAllPages, Get-ProxySettings and Remove-ODataInjectionChars
        # were already named this way before this branch, and other scripts may call them.
        'PSUseSingularNouns'
    )
}
