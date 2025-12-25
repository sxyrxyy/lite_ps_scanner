Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Helpers: IPv4 <-> uint32
# ----------------------------
function ConvertTo-UInt32IPv4 {
    param([Parameter(Mandatory)][string]$Ip)

    $p = $Ip.Split('.')
    if ($p.Count -ne 4) { throw "Invalid IPv4: $Ip" }

    $o = foreach ($x in $p) {
        if ($x -notmatch '^\d+$') { throw "Invalid IPv4: $Ip" }
        $n = [int]$x
        if ($n -lt 0 -or $n -gt 255) { throw "Invalid IPv4: $Ip" }
        $n
    }

    return ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
}

function ConvertFrom-UInt32IPv4 {
    param([Parameter(Mandatory)][uint32]$Value)
    "$(($Value -shr 24) -band 255).$(($Value -shr 16) -band 255).$(($Value -shr 8) -band 255).$($Value -band 255)"
}

# ----------------------------
# Generate IPs from CIDR or Range
# ----------------------------
function Get-IPRange {
    param(
        [Parameter(Mandatory)][string]$InputRange,
        [int]$MaxHosts = 65536
    )

    $ipList = New-Object System.Collections.Generic.List[string]

    # CIDR: 192.168.1.0/24
    if ($InputRange -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
        $parts  = $InputRange -split '/'
        $baseIP = $parts[0]
        $prefix = [int]$parts[1]
        if ($prefix -lt 0 -or $prefix -gt 32) { Write-Error "Invalid CIDR prefix: $prefix"; return @() }

        try { $ipInt = ConvertTo-UInt32IPv4 $baseIP } catch { Write-Error $_; return @() }

        $hostBits  = 32 - $prefix
        $hostCount = [uint64]1 -shl $hostBits

        if ($hostCount -gt [uint64]$MaxHosts) {
            Write-Error "Refusing to generate $hostCount hosts (cap: $MaxHosts)."
            return @()
        }

        $mask = if ($prefix -eq 0) { [uint32]0 } else { ([uint32]::MaxValue -shl $hostBits) }
        $networkInt = $ipInt -band $mask

        if ($prefix -eq 32) {
            $ipList.Add((ConvertFrom-UInt32IPv4 $networkInt))
            return $ipList
        }

        if ($prefix -eq 31) {
            $ipList.Add((ConvertFrom-UInt32IPv4 $networkInt))
            $ipList.Add((ConvertFrom-UInt32IPv4 ($networkInt + 1)))
            return $ipList
        }

        for ([uint32]$i = 1; $i -lt [uint32]($hostCount - 1); $i++) {
            $ipList.Add((ConvertFrom-UInt32IPv4 ($networkInt + $i)))
        }
        return $ipList
    }

    # Range: 192.168.1.10-192.168.1.50
    if ($InputRange -match '^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$') {
        $parts   = $InputRange -split '-'
        $startIP = $parts[0]
        $endIP   = $parts[1]

        try {
            $startInt = ConvertTo-UInt32IPv4 $startIP
            $endInt   = ConvertTo-UInt32IPv4 $endIP
        } catch { Write-Error $_; return @() }

        if ($startInt -gt $endInt) { Write-Error "Start IP must be <= end IP"; return @() }

        $count = [uint64]$endInt - [uint64]$startInt + 1
        if ($count -gt [uint64]$MaxHosts) {
            Write-Error "Refusing to generate $count hosts (cap: $MaxHosts)."
            return @()
        }

        for ([uint32]$i = $startInt; $i -le $endInt; $i++) {
            $ipList.Add((ConvertFrom-UInt32IPv4 $i))
        }
        return $ipList
    }

    Write-Error "Invalid format. Use CIDR (e.g., 192.168.1.0/24) or range (e.g., 192.168.1.1-192.168.1.254)"
    return @()
}

# ----------------------------
# SMB share enumeration
# ----------------------------
function Get-SmbShares {
    param([Parameter(Mandatory)][string]$Ip)

    # Windows: net view
    $netCmd = Get-Command net -ErrorAction SilentlyContinue
    if ($netCmd) {
        $out = & net view "\\$Ip" 2>$null
        if (-not $out) { return @() }

        $shares = New-Object System.Collections.Generic.List[string]
        $in = $false

        foreach ($line in $out) {
            if ($line -match '^-{3,}') { $in = $true; continue }
            if ($line -match 'The command completed successfully') { break }
            if (-not $in) { continue }

            if ($line -match '^\s*([^\s]+)\s{2,}\S+') {
                $name = $Matches[1].Trim()
                if ($name) { $shares.Add($name) }
            }
        }

        return $shares.ToArray() | Select-Object -Unique
    }

    # Linux/macOS: smbclient if installed
    $smbclient = Get-Command smbclient -ErrorAction SilentlyContinue
    if ($smbclient) {
        $out = & smbclient -L "\\$Ip" -N 2>$null
        if (-not $out) { return @() }

        $shares = New-Object System.Collections.Generic.List[string]
        $in = $false
        foreach ($line in $out) {
            if ($line -match '^\s*Sharename\s+Type') { $in = $true; continue }
            if ($in -and $line -match '^\s*([^\s]+)\s+(\S+)\s*') {
                $name = $Matches[1].Trim()
                if ($name -and $name -ne '---------' -and $name -ne 'Sharename') { $shares.Add($name) }
            }
        }

        return $shares.ToArray() | Select-Object -Unique
    }

    return @()
}

# ----------------------------
# Scan one host
# ----------------------------
function Scan-Host {
    param(
        [Parameter(Mandatory)][string]$Ip,
        [int[]]$Ports,
        [int]$PingTimeoutMs = 1000,
        [int]$DnsTimeoutMs  = 1500,
        [int]$PortTimeoutMs = 900,
        [switch]$ScanPortsWithoutPing
    )

    $isUp = $false
    $hostname = "N/A"

    # Always keep as arrays
    $openPorts = New-Object System.Collections.Generic.List[int]
    $shares    = @()

    # Ping
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $res = $p.Send($Ip, $PingTimeoutMs)
        if ($res.Status -eq 'Success') { $isUp = $true }
    } catch { }

    # DNS
    if ($isUp -or $ScanPortsWithoutPing) {
        try {
            $t = [System.Net.Dns]::GetHostEntryAsync($Ip)
            if ($t.Wait($DnsTimeoutMs)) {
                $hn = $t.Result.HostName
                if ($hn -and $hn -ne $Ip) { $hostname = $hn }
            }
        } catch { }
    }

    # Ports
    if ($isUp -or $ScanPortsWithoutPing) {
        foreach ($port in $Ports) {
            $tcp = $null
            $ar = $null
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $ar = $tcp.BeginConnect($Ip, $port, $null, $null)

                if ($ar.AsyncWaitHandle.WaitOne($PortTimeoutMs, $false)) {
                    try { $tcp.EndConnect($ar) } catch { }
                    if ($tcp.Connected) { $openPorts.Add($port) }
                }
            } catch { }
            finally {
                try { if ($ar) { $ar.AsyncWaitHandle.Close() } } catch { }
                try { if ($tcp) { $tcp.Close(); $tcp.Dispose() } } catch { }
            }
        }
    }

    # If ping blocked but ports open, treat as live
    if (-not $isUp -and $openPorts.Count -gt 0) { $isUp = $true }

    # Shares if SMB open
    if ($openPorts.ToArray() -contains 445) {
        try { $shares = Get-SmbShares -Ip $Ip } catch { $shares = @() }
    }

    # IMPORTANT: force arrays even if single element
    [pscustomobject]@{
        IP        = $Ip
        Live      = $isUp
        Hostname  = $hostname
        OpenPorts = @($openPorts.ToArray())
        Shares    = @($shares)
    }
}

# ----------------------------
# Main
# ----------------------------
Write-Host "Network Scanner (Ping + Ports + SMB Shares)" -ForegroundColor Cyan
Write-Host "Supported formats:"
Write-Host "  CIDR : 192.168.1.0/24"
Write-Host "  Range: 192.168.1.10-192.168.1.200`n"

$rangeInput = (Read-Host "Enter range").Trim()

# Speed knobs
$throttleDefault = 64
$throttleInput = Read-Host "Parallel workers (PowerShell 7+). Default [$throttleDefault]"
$Throttle = if ($throttleInput -match '^\d+$' -and [int]$throttleInput -gt 0) { [int]$throttleInput } else { $throttleDefault }

$scanPortsNoPingInput = Read-Host "Scan ports even if ping fails? (y/N)"
$ScanPortsWithoutPing = ($scanPortsNoPingInput -match '^(y|yes)$')

$ports = @(21, 80, 443, 445, 3389, 5985)

$ipList = Get-IPRange -InputRange $rangeInput -MaxHosts 65536
if (-not $ipList -or $ipList.Count -eq 0) {
    Write-Host "No IPs to scan. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "`nGenerated $($ipList.Count) host IPs to scan." -ForegroundColor Green
Write-Host "First: $($ipList[0])   Last: $($ipList[-1])`n"

$total = $ipList.Count
$done = 0
$canParallel = ($PSVersionTable.PSVersion.Major -ge 7)

if ($canParallel) {
    $ipList |
        ForEach-Object -Parallel {
            Scan-Host -Ip $_ -Ports $using:ports -PingTimeoutMs 1000 -DnsTimeoutMs 1500 -PortTimeoutMs 900 -ScanPortsWithoutPing:($using:ScanPortsWithoutPing)
        } -ThrottleLimit $Throttle |
        ForEach-Object {
            $done++
            Write-Progress -Activity "Scanning hosts" -Status "Processed $done / $total" -PercentComplete ([int](($done / $total) * 100))

            $r = $_
            $open = @($r.OpenPorts)
            $sh   = @($r.Shares)

            if ($r.Live) {
                Write-Host "[$done/$total] $($r.IP) LIVE" -ForegroundColor Green

                if ($r.Hostname -and $r.Hostname -ne "N/A") {
                    Write-Host "    Hostname: $($r.Hostname)" -ForegroundColor White
                }

                if ($open.Count -gt 0) {
                    Write-Host "    Open ports: $($open -join ', ')" -ForegroundColor Cyan
                } else {
                    Write-Host "    Open ports: none" -ForegroundColor Yellow
                }

                if ($open -contains 445) {
                    if ($sh.Count -gt 0) {
                        Write-Host "    SMB shares: $($sh -join ', ')" -ForegroundColor Magenta
                    } else {
                        Write-Host "    SMB shares: none/denied" -ForegroundColor DarkYellow
                    }
                }
            } else {
                Write-Host "[$done/$total] $($r.IP) DOWN" -ForegroundColor DarkGray
            }

            Write-Host ""
        }

    Write-Progress -Activity "Scanning hosts" -Completed
}
else {
    Write-Warning "PowerShell < 7 detected. Running sequential (slower). Install PowerShell 7+ for parallel scanning."

    foreach ($ip in $ipList) {
        $done++
        Write-Progress -Activity "Scanning hosts" -Status "Processed $done / $total" -PercentComplete ([int](($done / $total) * 100))

        $r = Scan-Host -Ip $ip -Ports $ports -PingTimeoutMs 1000 -DnsTimeoutMs 1500 -PortTimeoutMs 900 -ScanPortsWithoutPing:($ScanPortsWithoutPing)

        $open = @($r.OpenPorts)
        $sh   = @($r.Shares)

        if ($r.Live) {
            Write-Host "[$done/$total] $($r.IP) LIVE" -ForegroundColor Green

            if ($r.Hostname -and $r.Hostname -ne "N/A") {
                Write-Host "    Hostname: $($r.Hostname)" -ForegroundColor White
            }

            if ($open.Count -gt 0) {
                Write-Host "    Open ports: $($open -join ', ')" -ForegroundColor Cyan
            } else {
                Write-Host "    Open ports: none" -ForegroundColor Yellow
            }

            if ($open -contains 445) {
                if ($sh.Count -gt 0) {
                    Write-Host "    SMB shares: $($sh -join ', ')" -ForegroundColor Magenta
                } else {
                    Write-Host "    SMB shares: none/denied" -ForegroundColor DarkYellow
                }
            }
        } else {
            Write-Host "[$done/$total] $($r.IP) DOWN" -ForegroundColor DarkGray
        }

        Write-Host ""
    }

    Write-Progress -Activity "Scanning hosts" -Completed
}

Write-Host "Scan complete. Processed $total hosts." -ForegroundColor Green
