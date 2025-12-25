function Get-IPRange {
    param (
        [string]$InputRange
    )

    $ipList = @()

    # CIDR notation: e.g., 192.168.1.0/24
    if ($InputRange -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
        $parts = $InputRange -split '/'
        $baseIP = $parts[0]
        $prefix = [int]$parts[1]

        if ($prefix -lt 0 -or $prefix -gt 32) {
            Write-Error "Invalid CIDR prefix: $prefix (must be 0-32)"
            return @()
        }

        # Convert base IP to integer
        $ipParts = $baseIP -split '\.'
        $ipInt = ([uint32]$ipParts[0] -shl 24) + 
                 ([uint32]$ipParts[1] -shl 16) + 
                 ([uint32]$ipParts[2] -shl 8)  + 
                 [uint32]$ipParts[3]

        # Calculate network address and broadcast
        $hostBits = 32 - $prefix
        $hostCount = [math]::Pow(2, $hostBits)
        $mask = [uint32](0xFFFFFFFF -shl $hostBits) -shr $hostBits  # Correct mask
        $networkInt = $ipInt -band (0xFFFFFFFF -shl $hostBits)
        $broadcastInt = $networkInt + $hostCount - 1

        # For /31 and /32, no host IPs to scan (RFC 3021), so warn and return empty
        if ($hostCount -le 2) {
            Write-Warning "CIDR $InputRange has no scannable host addresses (/$prefix)."
            return @()
        }

        # Generate IPs from network+1 to broadcast-1
        for ($i = 1; $i -lt ($hostCount - 1); $i++) {
            $hostInt = $networkInt + $i
            $oct1 = ($hostInt -shr 24) -band 255
            $oct2 = ($hostInt -shr 16) -band 255
            $oct3 = ($hostInt -shr 8)  -band 255
            $oct4 = $hostInt -band 255
            $ipList += "$oct1.$oct2.$oct3.$oct4"
        }
        return $ipList
    }
    # Range format: 192.168.1.1-192.168.1.254
    elseif ($InputRange -match '^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$') {
        $parts = $InputRange -split '-'
        $startIP = $parts[0]
        $endIP = $parts[1]

        $startParts = $startIP -split '\.'
        $endParts = $endIP -split '\.'

        $startInt = ([uint32]$startParts[0] -shl 24) + 
                    ([uint32]$startParts[1] -shl 16) + 
                    ([uint32]$startParts[2] -shl 8)  + 
                    [uint32]$startParts[3]

        $endInt = ([uint32]$endParts[0] -shl 24) + 
                  ([uint32]$endParts[1] -shl 16) + 
                  ([uint32]$endParts[2] -shl 8)  + 
                  [uint32]$endParts[3]

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

Write-Host "Network Scanner with Hostname Resolution" -ForegroundColor Cyan
Write-Host "Supported formats:"
Write-Host "  CIDR: 192.168.1.0/24   (scans .1 to .254)"
Write-Host "  Range: 192.168.1.1-192.168.1.254`n"

$rangeInput = Read-Host "Enter range"

$ipList = Get-IPRange -InputRange $rangeInput.Trim()

if ($ipList.Count -eq 0) {
    Write-Host "No IPs to scan. Exiting." -ForegroundColor Red
    exit
}

Write-Host "Generated $($ipList.Count) host IPs to scan." -ForegroundColor Green
Write-Host "First: $($ipList[0])   Last: $($ipList[-1])`n"

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

            # Hostname resolution
            $hostname = "N/A"
            try {
                $resolveTask = [System.Net.Dns]::GetHostEntryAsync($ip)
                if ($resolveTask.Wait(1500)) {
                    $resolved = $resolveTask.Result.HostName
                    if ($resolved -and $resolved -ne $ip) {
                        $hostname = $resolved
                    }
                }
            } catch { }

            if ($hostname -ne "N/A") {
                Write-Host "    Hostname: $hostname" -ForegroundColor White
            }

            # Port checking
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

            # SMB shares
            if ($openPorts -contains 445) {
                Write-Host "    Checking SMB shares ..." -NoNewline
                try {
                    $output = net view \\$ip 2>$null
                    if ($output) {
                        $shares = @()
                        $inShares = $false
                        foreach ($line in $output) {
                            if ($line -match "^Share name") { $inShares = $true; continue }
                            if ($inShares -and $line -match "^[A-Za-z\$]") {
                                $shareName = ($line -split '\s+')[0].Trim()
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
