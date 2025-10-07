<#
.SYNOPSIS
    Query the AbuseIPDB API for one or more IP addresses without requiring third-party modules.

.DESCRIPTION
    This PowerShell script mirrors the core functionality of the Python CLI that ships with this
    repository.  It resolves the AbuseIPDB API key from a parameter, the ABUSEIPDB_API_KEY
    environment variable, or an interactive prompt, then queries the AbuseIPDB API for each
    provided IP address.  Results may be displayed in a formatted table or exported to CSV.

.PARAMETER IpAddress
    A list of IP addresses to query.  You can also pipe strings into the script.

.PARAMETER InputFile
    Optional path to a text/CSV file that contains IP addresses.  The script accepts one IP per
    line or comma/semicolon separated values.

.PARAMETER OutputFile
    Optional path to write results to CSV instead of printing a table to the console.

.PARAMETER ExcludeConfidenceLessThan100
    When set, the script only emits entries whose abuseConfidenceScore is exactly 100.

.EXAMPLE
    PS> .\AbuseIPDBQuickCheck.ps1 -IpAddress 1.1.1.1, 8.8.8.8

.EXAMPLE
    PS> Get-Content ips.txt | .\AbuseIPDBQuickCheck.ps1 -OutputFile results.csv

.NOTES
    The script uses only built-in PowerShell cmdlets such as Invoke-RestMethod and can run on
    Windows PowerShell 5.1 or PowerShell 7+ without installing additional modules.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('IP', 'IPAddress')]
    [string[]]$IpAddress,

    [Parameter()]
    [string]$InputFile,

    [Parameter()]
    [string]$OutputFile,

    [Parameter()]
    [switch]$ExcludeConfidenceLessThan100,

    [Parameter()]
    [string]$ApiKey
)

begin {
    $script:CollectedIps = New-Object System.Collections.Generic.List[string]
}

process {
    if ($null -ne $IpAddress) {
        foreach ($ip in $IpAddress) {
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }
            $script:CollectedIps.Add($ip)
        }
    }
}

end {
    function Resolve-ApiKey {
        param([string]$ProvidedKey)

        if ($ProvidedKey -and -not [string]::IsNullOrWhiteSpace($ProvidedKey)) {
            return $ProvidedKey.Trim()
        }

        if ($env:ABUSEIPDB_API_KEY) {
            $candidate = $env:ABUSEIPDB_API_KEY.Trim()
            if ($candidate) { return $candidate }
        }

        $secure = Read-Host -Prompt 'Enter your AbuseIPDB API key' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    function Get-NormalizedIp {
        param([string]$Ip)
        if ([string]::IsNullOrWhiteSpace($Ip)) { return $null }
        $trimmed = $Ip.Trim().Trim("'\"")
        if (-not $trimmed) { return $null }
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($trimmed, [ref]$parsed)) {
            return $trimmed
        }
        return $null
    }

    function Read-IpsFromFile {
        param([string]$Path)

        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Input file not found: $Path"
        }

        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
        $results = New-Object System.Collections.Generic.List[string]
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $pieces = $line -split '[;,]'
            foreach ($piece in $pieces) {
                $ip = Get-NormalizedIp -Ip $piece
                if ($ip) { $results.Add($ip) }
            }
        }
        return $results
    }

    function Invoke-AbuseIpdbCheck {
        param(
            [Parameter(Mandatory = $true)][string]$Ip,
            [Parameter(Mandatory = $true)][string]$Key
        )

        $uri = 'https://api.abuseipdb.com/api/v2/check'
        $requestUri = '{0}?ipAddress={1}' -f $uri, [System.Uri]::EscapeDataString($Ip)
        $headers = @{ Accept = 'application/json'; Key = $Key }
        try {
            $response = Invoke-RestMethod -Method Get -Uri $requestUri -Headers $headers -ErrorAction Stop
            $data = $response.data
            if (-not $data) {
                return [PSCustomObject]@{
                    ipAddress            = $Ip
                    abuseConfidenceScore = 'N/A'
                    totalReports         = 'N/A'
                    domain               = 'No data returned'
                    countryCode          = 'N/A'
                    usageType            = 'N/A'
                    isTor                = 'N/A'
                }
            }
            return [PSCustomObject]@{
                ipAddress            = $data.ipAddress
                abuseConfidenceScore = $data.abuseConfidenceScore
                totalReports         = $data.totalReports
                domain               = $data.domain
                countryCode          = $data.countryCode
                usageType            = $data.usageType
                isTor                = $data.isTor
            }
        }
        catch {
            return [PSCustomObject]@{
                ipAddress            = $Ip
                abuseConfidenceScore = 'ERR'
                totalReports         = '-'
                domain               = $_.Exception.Message
                countryCode          = '-'
                usageType            = '-'
                isTor                = '-'
            }
        }
    }

    function Select-EffectiveIps {
        param(
            [System.Collections.Generic.List[string]]$Collected,
            [string]$InputPath
        )

        $allIps = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Collected) {
            $ip = Get-NormalizedIp -Ip $item
            if ($ip) { $allIps.Add($ip) }
        }

        if ($InputPath) {
            $fromFile = Read-IpsFromFile -Path $InputPath
            foreach ($item in $fromFile) { $allIps.Add($item) }
        }

        if ($allIps.Count -eq 0) {
            $manual = Read-Host 'Enter IPs (comma or semicolon separated). Leave blank to exit'
            if (-not $manual) { return @() }
            foreach ($piece in ($manual -split '[;,]')) {
                $ip = Get-NormalizedIp -Ip $piece
                if ($ip) { $allIps.Add($ip) }
            }
        }

        return $allIps
    }

    $resolvedKey = Resolve-ApiKey -ProvidedKey $ApiKey
    if (-not $resolvedKey) {
        Write-Error 'No API key provided. Aborting.'
        return
    }

    try {
        $ips = Select-EffectiveIps -Collected $script:CollectedIps -InputPath $InputFile
    }
    catch {
        Write-Error $_.Exception.Message
        return
    }

    if ($ips.Count -eq 0) {
        Write-Host 'No IP addresses to process. Exiting.'
        return
    }

    $results = New-Object System.Collections.Generic.List[object]
    $total = $ips.Count
    $index = 0
    foreach ($ip in $ips) {
        $index++
        Write-Progress -Activity 'Querying AbuseIPDB' -Status "Processing $ip ($index of $total)" -PercentComplete (($index / $total) * 100)
        $results.Add((Invoke-AbuseIpdbCheck -Ip $ip -Key $resolvedKey))
    }
    Write-Progress -Activity 'Querying AbuseIPDB' -Completed -Status 'Done'

    $finalResults = if ($ExcludeConfidenceLessThan100) {
        $results | Where-Object {
            $score = $_.abuseConfidenceScore
            $parsedScore = 0
            [int]::TryParse([string]$score, [ref]$parsedScore) -and $parsedScore -eq 100
        }
    } else {
        $results
    }

    if ($OutputFile) {
        try {
            $finalResults | Export-Csv -LiteralPath $OutputFile -NoTypeInformation -Encoding UTF8
            Write-Host "Wrote $($finalResults.Count) rows to '$OutputFile'."
        }
        catch {
            Write-Error "Failed to write CSV '$OutputFile': $($_.Exception.Message)"
        }
    }
    else {
        $finalResults | Format-Table ipAddress, abuseConfidenceScore, totalReports, domain, countryCode, usageType, isTor -AutoSize
    }
}
