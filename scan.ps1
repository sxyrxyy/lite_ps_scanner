function Get-IPRange {
    param (
        [string]$InputRange
    )

    $ipList = @()

    # CIDR notation: e.g., 192.168.1.0/24
    if ($InputRange -match '^\d+\.\d+\.\d+\.\d+/\d+$') {
        $parts = $InputRange -split '/'
        $baseIP = $parts[0]
        $prefix = [int]$parts[1]

        if ($prefix -lt 0 -or $prefix -gt 32) {
            Write-Error "Invalid CIDR prefix: $prefix (must be 0-32)"
            return @()
        }

        $ipParts = $baseIP -split '\.'
        $ipInt = ([int]$ipParts[0] -shl 24) + 
                 ([int]$ipParts[1] -shl 16) + 
                 ([int]$ipParts[2] -shl 8)  + 
                 [int]$ipParts[3]

        $mask = (-bnot ((1 -shl (32 - $prefix)) - 1)) -band [uint32]::MaxValue
        $networkInt = $ipInt -band $mask
        $hostMax = ([math]::Pow(2, (32 - $prefix))) - 1

        if ($hostMax -le 1) {  # /31 or /32 has no usable hosts for scanning
            Write-Warning "CIDR $InputRange has no scannable hosts (/$prefix)."
            return @()
        }

        for ($i = 1; $i -lt $hostMax; $i++) {
            $hostInt = $networkInt + $i
            $oct1 = ($hostInt -shr 24) -band 255
            $oct2 = ($hostInt -shr 16) -band 255
            $oct3 = ($hostInt -shr 8)  -band 255
            $oct4 = $hostInt -band 255
            $ipList += "$oct1.$oct2.$oct3.$oct4"
        }
        return $ipList
    }
    # Range format: startIP-endIP
    elseif ($InputRange -match '^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$') {
        $parts = $InputRange -split '-'
        $startIP = $parts[0]
        $endIP = $parts[1]

        $startParts = $startIP -split '\.'
        $endParts = $endIP -split '\.'

        $startInt = ([int]$startParts[0] -shl 24) + 
                    ([int]$startParts[1] -shl 16) + 
                    ([int]$startParts[2] -shl 8)  + 
                    [int]$startParts[3]

        $endInt = ([int]$endParts[0] -shl 24) + 
                  ([int]$endParts[1] -shl 16) + 
                  ([int]$endParts[2] -shl 8)  + 
                  [int]$endParts[3]

        if ($startInt -gt $endInt) {
            Write-Error "Start IP must be less than or equal to end IP"
            return @()
        }

        for ($i = $startInt; $i -le $endInt; $i++) {
            $oct1 = ($i -shr 24) -band 255
            $oct2 = ($i -shr 16) -band 255
            $oct3 = ($i -shr 8)  -band 255
            $oct4 = $i -band 255
            $ipList += "$oct1.$oct2.$oct3.$oct4"
        }
        return $ipList
    }
    else {
        Write-Error "Invalid format. Use CIDR (e.g., 192.168.1.0/24) or range (e.g., 192.168.1.1-192.168.1.254)"
        return @()
    }
}

# === Main Script ===

Write-Host "Network Scanner" -ForegroundColor Cyan
Write-Host "Supported formats:"
Write-Host "  CIDR: 192.168.1.0/24"
Write-Host "  Range: 192.168.1.1-192.168.1.254`n"

$rangeInput = Read-Host "Enter range"

$ipList = Get-IPRange -InputRange $rangeInput.Trim()

if ($ipList.Count -eq 0) {
    Write-Host "No IPs to scan. Exiting." -ForegroundColor Red
    exit
}

Write-Host "Scanning $($ipList.Count) hosts..." -ForegroundColor Green
Write-Host ""

$ports = @(21, 80, 443, 445, 3389, 5985)
$total = $ipList.Count
$current = 0

foreach ($ip in $ipList) {
    $current++
    Write-Host "[$current/$total] $ip ..." -NoNewline

    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $result = $ping.Send($ip, 1000)
        if ($result.Status -eq 'Success') {
            Write-Host " LIVE" -ForegroundColor Green

            Write-Host "    Checking ports $($ports -join ', ') ..." -NoNewline
            $openPorts = @()

            foreach ($port in $ports) {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($ip, $port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
                if ($wait -and $tcp.Connected) {
                    $openPorts += $port
                }
                if ($tcp.Connected) { $tcp.Close() }
            }

            if ($openPorts.Count -gt 0) {
                Write-Host " Open: $($openPorts -join ', ')" -ForegroundColor Cyan
            } else {
                Write-Host " None open" -ForegroundColor Yellow
            }

            if ($openPorts -contains 445) {
                Write-Host "    Checking SMB shares ..." -NoNewline
                try {
                    $output = net view \\$ip 2>$null
                    if ($output) {
                        $shares = @()
                        $inShares = $false
                        foreach ($line in $output) {
                            if ($line -match "^Share name") { $inShares = $true; continue }
                            if ($inShares -and $line -match "^[A-Za-z]") {
                                $shareName = ($line -split '\s+')[0]
                                if ($shareName) { $shares += $shareName }
                            }
                            if ($line -match "The command completed successfully") { break }
                        }
                        if ($shares.Count -gt 0) {
                            Write-Host " Shares: $($shares -join ', ')" -ForegroundColor Magenta
                        } else {
                            Write-Host " None accessible"
                        }
                    } else {
                        Write-Host " Access denied"
                    }
                } catch {
                    Write-Host " Error: $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host " DOWN" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host " PING FAIL" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "Scan complete. Processed $total hosts." -ForegroundColor Green
