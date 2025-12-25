# Function to generate IP list from CIDR or start/end range
function Get-IPRange {
    param (
        [string]$InputRange
    )

    # Check if it's CIDR notation (contains '/')
    if ($InputRange -match '/\d+$') {
        # CIDR format
        $cidrParts = $InputRange -split '/'
        $baseIP = $cidrParts[0]
        $prefix = [int]$cidrParts[1]

        if ($prefix -lt 0 -or $prefix -gt 32) {
            Write-Error "Invalid CIDR prefix length: $prefix"
            return @()
        }

        # Calculate network address and number of hosts
        $ipParts = $baseIP -split '\.'
        $ipInt = ([int]$ipParts[0] -shl 24) + ([int]$ipParts[1] -shl 16) + ([int]$ipParts[2] -shl 8) + [int]$ipParts[3]
        $mask = -bnot ((1 -shl (32 - $prefix)) - 1)
        $networkInt = $ipInt -band $mask
        $hostCount = [Math]::Pow(2, (32 - $prefix)) - 1  # Exclude network and broadcast

        $ipList = @()
        for ($i = 1; $i -lt $hostCount; $i++) {  # Start from +1 to skip network address
            $hostInt = $networkInt + $i
            $ip = "{0}.{1}.{2}.{3}" -f (
                ($hostInt -shr 24) -band 255),
                ($hostInt -shr 16) -band 255),
                ($hostInt -shr 8)  -band 255),
                ($hostInt -band 255)
            $ipList += $ip
        }
        # Add broadcast if needed? Typically skipped for scanning
        return $ipList
    }
    else {
        # Assume start-end format: startIP-endIP
        if (-not ($InputRange -match '^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$')) {
            Write-Error "Invalid range format. Use CIDR (e.g., 192.168.1.0/24) or start-end (e.g., 192.168.1.1-192.168.1.254)"
            return @()
        }

        $parts = $InputRange -split '-'
        $startIP = $parts[0]
        $endIP = $parts[1]

        function IPToInt($ip) {
            $p = $ip.Split('.')
            return ([int]$p[0] -shl 24) + ([int]$p[1] -shl 16) + ([int]$p[2] -shl 8) + [int]$p[3]
        }

        $startInt = IPToInt $startIP
        $endInt = IPToInt $endIP
        if ($startInt -gt $endInt) {
            Write-Error "Start IP must be less than or equal to end IP"
            return @()
        }

        $ipList = @()
        for ($i = $startInt; $i -le $endInt; $i++) {
            $ipList += "{0}.{1}.{2}.{3}" -f (
                ($i -shr 24) -band 255),
                ($i -shr 16) -band 255),
                ($i -shr 8)  -band 255),
                ($i -band 255)
        }
        return $ipList
    }
}

# Prompt for range input
Write-Host "Enter IP range to scan:" -ForegroundColor Cyan
Write-Host "Examples:"
Write-Host "  CIDR: 192.168.1.0/24"
Write-Host "  Range: 192.168.1.1-192.168.1.254" -ForegroundColor Gray

$rangeInput = Read-Host "Range"

$ipList = Get-IPRange -InputRange $rangeInput

if ($ipList.Count -eq 0) {
    Write-Host "No valid IPs generated. Exiting." -ForegroundColor Red
    exit
}

Write-Host "Generated $($ipList.Count) IP addresses to scan." -ForegroundColor Green
Write-Host ""

# Ports to check
$ports = @(21, 80, 443, 445, 3389, 5985)

# Progress counter
$total = $ipList.Count
$current = 0

foreach ($ip in $ipList) {
    $current++
    Write-Host "[$current/$total] Scanning $ip ..." -NoNewline

    # Fast ping with 1-second timeout
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $pingResult = $ping.Send($ip, 1000)
        if ($pingResult.Status -eq 'Success') {
            Write-Host " LIVE" -ForegroundColor Green

            # Check ports with 1-second timeout each
            Write-Host "    Checking ports ($($ports -join ', ')) ..." -NoNewline
            $openPorts = @()
            foreach ($port in $ports) {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($ip, $port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
                if ($wait -and $tcpClient.Connected) {
                    $openPorts += $port
                    $tcpClient.Close()
                } elseif ($tcpClient.Connected) {
                    $tcpClient.Close()
                }
            }

            if ($openPorts.Count -gt 0) {
                Write-Host " Open: $($openPorts -join ', ')" -ForegroundColor Cyan
            } else {
                Write-Host " No specified ports open." -ForegroundColor Yellow
            }

            # SMB share enumeration if 445 open
            if ($openPorts -contains 445) {
                Write-Host "    SMB open. Checking shares..." -NoNewline
                try {
                    $netViewOutput = net view \\$ip 2>$null
                    if ($netViewOutput) {
                        $sharesFound = $false
                        $shares = @()
                        for ($j = 0; $j -lt $netViewOutput.Length; $j++) {
                            if ($netViewOutput[$j] -match "^The command completed successfully\.$") { break }
                            if ($sharesFound -and $netViewOutput[$j].Trim() -ne "") {
                                $shareName = ($netViewOutput[$j] -split '\s+')[0]
                                if ($shareName) { $shares += $shareName }
                            }
                            if ($netViewOutput[$j] -match "^Share name") {
                                $sharesFound = $true
                                $j++  # Skip header underline
                            }
                        }
                        if ($shares.Count -gt 0) {
                            Write-Host " Shares: $($shares -join ', ')" -ForegroundColor Magenta
                        } else {
                            Write-Host " No shares accessible."
                        }
                    } else {
                        Write-Host " Access denied or no shares."
                    }
                } catch {
                    Write-Host " Error: $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host " DOWN" -ForegroundColor Red
        }
    } catch {
        Write-Host " DOWN (ping failed)" -ForegroundColor Red
    }

    Write-Host ""  # Blank line for readability
}

Write-Host "Scan completed. Scanned $total hosts." -ForegroundColor Green
