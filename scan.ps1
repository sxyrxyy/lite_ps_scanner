# Prompt for start and end IP
$startIP = Read-Host "Enter the starting IP address (e.g., 192.168.1.1)"
$endIP = Read-Host "Enter the ending IP address (e.g., 192.168.1.254)"

# Function to convert IP to integer
function IPToInt {
    param ($ip)
    $parts = $ip.Split('.')
    return ([int]$parts[0] * 16777216) + ([int]$parts[1] * 65536) + ([int]$parts[2] * 256) + [int]$parts[3]
}

# Function to convert integer to IP
function IntToIP {
    param ($int)
    return "{0}.{1}.{2}.{3}" -f ([math]::Floor($int / 16777216) % 256), ([math]::Floor($int / 65536) % 256), ([math]::Floor($int / 256) % 256), ($int % 256)
}

# Generate IP list
$startInt = IPToInt $startIP
$endInt = IPToInt $endIP
$ipList = @()
for ($i = $startInt; $i -le $endInt; $i++) {
    $ipList += IntToIP $i
}

# Ports to check
$ports = @(21, 80, 443, 445, 3389, 5985)

# Scan each IP
foreach ($ip in $ipList) {
    # Check if host is live
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        Write-Host "Host $ip is live." -ForegroundColor Green
        
        # Check open ports
        $openPorts = @()
        foreach ($port in $ports) {
            $result = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
            if ($result.TcpTestSucceeded) {
                $openPorts += $port
            }
        }
        
        if ($openPorts.Count -gt 0) {
            Write-Host "Open ports: $($openPorts -join ', ')"
        } else {
            Write-Host "No specified ports open."
        }
        
        # If SMB (445) is open, check shares
        if ($openPorts -contains 445) {
            Write-Host "SMB is open. Checking available shares..."
            try {
                $netViewOutput = net view \\$ip 2>$null
                if ($netViewOutput) {
                    $sharesFound = $false
                    $shares = @()
                    for ($j = 0; $j -lt $netViewOutput.Length; $j++) {
                        if ($netViewOutput[$j] -match "^The command completed successfully\.$") {
                            break
                        }
                        if ($sharesFound) {
                            if ($netViewOutput[$j].Trim() -eq "") { break }
                            $shareName = $netViewOutput[$j].Split(' ')[0]
                            $shares += $shareName
                        }
                        if ($netViewOutput[$j] -match "^Share name") {
                            $sharesFound = $true
                            $j++  # Skip the header line
                        }
                    }
                    if ($shares.Count -gt 0) {
                        Write-Host "Available shares: $($shares -join ', ')"
                    } else {
                        Write-Host "No shares found or access denied."
                    }
                } else {
                    Write-Host "No shares found or access denied."
                }
            } catch {
                Write-Host "Error checking shares: $_" -ForegroundColor Red
            }
        }
        Write-Host ""
    } else {
        Write-Host "Host $ip is not responding." -ForegroundColor Yellow
    }
}

Write-Host "Scan completed." -ForegroundColor Green
