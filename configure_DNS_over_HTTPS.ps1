<#
    configure_DNS_over_HTTPS.ps1

    Complete DNS over HTTPS Configuration Script

    (updated for powershell 5.1 compatibility)

    WHAT THIS DOES
    --------------
    - Tri-state per target:
        WindowsDoH : Unchanged | Enable | Disable
        ChromeDoH  : Unchanged | Enable | Disable  (per-user HKCU policy)
        FirefoxDoH : Unchanged | Enable | Disable  (per-user user.js)
    - Windows-specific policy:
        WindowsPolicy : Unchanged | Off | Allow | Require
      (When enabling and policy = Require, we first apply Allow, verify resolution,
       then promote to Require only if safe.)
    - Windows adapter DNS IPs are NOT changed unless you explicitly request it:
        - ApplyAdapterDNS: if present AND Primary/Secondary DNS are supplied, we set adapter IPv4 DNS
        - Otherwise adapter DNS remains unchanged (we only register DoH templates and set policy)
    - Safety checks (always on):
        - TCP/53 liveness to candidate IPs (plaintext DNS fallback viability)
        - TCP/443 reachability to each DoH hostname
        - Real DoH probe: send an RFC 8484 application/dns-message query and validate the response
        - Two-phase Windows policy apply (Allow -> test -> Require)
        - Block Require when template unknown or probes fail

    IMPORTANT CONCEPTS
    ------------------
    - Windows DoH uses the adapter DNS IPs as the "identity" of the resolver.
      A DoH template URL is registered for each IP (IP -> HTTPS template).
      Policy chooses transport: Off (plaintext), Allow (prefer DoH, fallback allowed), Require (DoH only).
    - Browsers:
      - When browser DoH is ENABLED, Chrome/Firefox talk DIRECTLY to their DoH endpoint(s).
      - When browser DoH is DISABLED, the browser uses the OS resolver (Windows), which may itself use DoH depending on OS policy.

    DEFAULTS
    --------
    - Safe Mode: always on (no switch to disable in this script)
    - No default DNS IPs are applied. If you want to change adapter DNS, pass:
        -ApplyAdapterDNS -PrimaryDNS <ip> -SecondaryDNS <ip>

    EXAMPLES
    --------
    # 1) Windows DoH Enable using CURRENT adapter DNS (no change of adapter IPs):
    #    Register templates for recognized current DNS IPs; set Allow; test; promote to Require.
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
      -File ".\configure_DNS_over_HTTPS.ps1" `
      -WindowsDoH Enable -WindowsPolicy Require

    # 2) Firefox DoH only (per-user), leave Windows unchanged:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
      -File ".\configure_DNS_over_HTTPS.ps1" `
      -FirefoxDoH Enable

    # 3) Chrome DoH only (per-user), leave Windows unchanged:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
      -File ".\configure_DNS_over_HTTPS.ps1" `
      -ChromeDoH Enable

    # 4) Change adapter DNS to Cloudflare + Quad9 (WITHOUT touching Windows DoH policy):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
      -File ".\configure_DNS_over_HTTPS.ps1" `
      -ApplyAdapterDNS -PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9

    # 5) Windows DoH Disable (policy Off), keep adapter DNS as-is:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
      -File ".\configure_DNS_over_HTTPS.ps1" `
      -WindowsDoH Disable
#>

[CmdletBinding()]
param(
    # Optional: only used if -ApplyAdapterDNS is specified
    [ipaddress]$PrimaryDNS    = $null,
    [ipaddress]$SecondaryDNS  = $null,

    [ValidateSet('Unchanged','Enable','Disable')][string]$WindowsDoH     = 'Unchanged',
    [ValidateSet('Unchanged','Off','Allow','Require')][string]$WindowsPolicy = 'Unchanged',

    [ValidateSet('Unchanged','Enable','Disable')][string]$ChromeDoH      = 'Unchanged',
    [ValidateSet('Unchanged','Enable','Disable')][string]$FirefoxDoH     = 'Unchanged',

    # Explicitly apply adapter IPv4 DNS to the system (independent of DoH policy)
    [switch]$ApplyAdapterDNS
)

# ------------------------------------------------------------------------
# Enums (tri-state + Windows policy)
# ------------------------------------------------------------------------
enum TriState    { Unchanged; Enable; Disable }
enum WinDohPolicy { Unchanged; Off; Allow; Require }

# Cast incoming string parameters to enums for internal use
$WindowsDoH   = [TriState]::$WindowsDoH
$WindowsPolicy= [WinDohPolicy]::$WindowsPolicy
$ChromeDoH    = [TriState]::$ChromeDoH
$FirefoxDoH   = [TriState]::$FirefoxDoH

# ------------------------------------------------------------------------
# Globals / Helpers
# ------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$script:HadError       = $false

function Write-Headline($text) { Write-Host $text -ForegroundColor Cyan }
function Write-Info($text)     { Write-Host $text -ForegroundColor White }
function Write-OK($text)       { Write-Host $text -ForegroundColor Green }
function Write-Warn($text)     { Write-Host $text -ForegroundColor Yellow }
function Write-Err($text)      { Write-Host $text -ForegroundColor Red }

# ------------------------------------------------------------------------
# Known IPv4 DNS -> DoH Template mapping.
# Add to this as you verify providers. If a template is unknown, we can still run with Allow,
# ... but Require will be blocked from being implemented so as to avoid breaking DNS on the PC.
$dnsToDohMap = @{
    # Aussie Broadband (ABB)
    '202.142.142.142' = 'https://dnscache1.aussiebroadband.com.au/dns-query'
    '202.142.142.242' = 'https://dnscache2.aussiebroadband.com.au/dns-query'

    # Cloudflare (standard)
    '1.1.1.1'         = 'https://cloudflare-dns.com/dns-query'
    '1.0.0.1'         = 'https://cloudflare-dns.com/dns-query'

    # Cloudflare (security)
    '1.1.1.2'         = 'https://security.cloudflare-dns.com/dns-query'
    '1.0.0.2'         = 'https://security.cloudflare-dns.com/dns-query'

    # Cloudflare (family)
    '1.1.1.3'         = 'https://family.cloudflare-dns.com/dns-query'
    '1.0.0.3'         = 'https://family.cloudflare-dns.com/dns-query'

    # Google Public DNS
    '8.8.8.8'         = 'https://dns.google/dns-query'
    '8.8.4.4'         = 'https://dns.google/dns-query'

    # Quad9
    '9.9.9.9'         = 'https://dns.quad9.net/dns-query'
    '149.112.112.112' = 'https://dns.quad9.net/dns-query'

    # OpenDNS (Cisco)
    '208.67.222.222'  = 'https://doh.opendns.com/dns-query'
    '208.67.220.220'  = 'https://doh.opendns.com/dns-query'

    # AdGuard
    '94.140.14.14'    = 'https://dns.adguard.com/dns-query'
    '94.140.15.15'    = 'https://dns.adguard.com/dns-query'

    # CleanBrowsing (Family filter; add others as needed)
    '185.228.168.168' = 'https://doh.cleanbrowsing.org/dns-query'
    '185.228.169.168' = 'https://doh.cleanbrowsing.org/dns-query'
}

# ------------------------------------------------------------------------
# Utility: gather current Windows Adapter IPv4 DNS IPs (unique)
# ------------------------------------------------------------------------
function Get-CurrentAdapterDnsIPv4 {
    try {
        $rows = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
        $ips = @()
        foreach ($r in $rows) {
            foreach ($ip in $r.ServerAddresses) {
                if ($ip -and $ip -ne '0.0.0.0') { $ips += $ip }
            }
        }
        return ($ips | Select-Object -Unique)
    } catch {
        Write-Warn ("Could not enumerate Windows Adapter DNS IPv4 addresses: {0}" -f $_.Exception.Message)
        return @()
    }
}

# ------------------------------------------------------------------------
# Utility: TCP/53 reachability (plaintext DNS liveness)
# ------------------------------------------------------------------------
function Test-PlainDnsTcp {
    param([string]$ServerIP)

    try {
        # Use a real DNS query over TCP (skip UDP since it may be blocked).
        $res = Resolve-DnsName -Server $ServerIP -TcpOnly -DnsOnly -Type A -Name "example.com" -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# ------------------------------------------------------------------------
# Utility: extract DoH host from template URL and test TCP/443
# ------------------------------------------------------------------------
function Get-DohHost {
    param([string]$Template)
    try   { return ([uri]$Template).Host } catch { return $null }
}

function Test-Tcp443 {
    param([string]$Host)
    try {
        $r = Test-NetConnection -ComputerName $Host -Port 443 -InformationLevel Quiet
        return [bool]$r
    } catch { return $false }
}

# ------------------------------------------------------------------------
# DNS query builder (application/dns-message)
# Build a minimal standard recursive query for A record (example.com)
# ------------------------------------------------------------------------
function New-DnsQueryBytes {
    param(
        [string]$Name = 'example.com',
        [ValidateSet('A','AAAA','NS','CNAME','MX','TXT')] [string]$QType = 'A'
    )
    # Header: 12 bytes
    $rand = (New-Object System.Random).Next(0,0xFFFF)
    $idHi = ($rand -band 0xFF00) -shr 8
    $idLo =  $rand -band 0x00FF
    # Flags: 0x0100 (standard query, RD=1)
    $flagsHi = 0x01
    $flagsLo = 0x00
    $qdcountHi,$qdcountLo = 0x00,0x01
    $ancountHi,$ancountLo = 0x00,0x00
    $nscountHi,$nscountLo = 0x00,0x00
    $arcountHi,$arcountLo = 0x00,0x00

    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.AddRange([byte[]]@($idHi,$idLo,$flagsHi,$flagsLo,$qdcountHi,$qdcountLo,$ancountHi,$ancountLo,$nscountHi,$nscountLo,$arcountHi,$arcountLo))

    # QNAME: label lengths + label bytes + 0x00
    foreach ($label in $Name.Split('.')) {
        $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$lb.Length)
        $bytes.AddRange($lb)
    }
    $bytes.Add(0x00)

    # QTYPE
    $qtypeMap = @{ A=1; AAAA=28; NS=2; CNAME=5; MX=15; TXT=16 }
    $qcode = [int]$qtypeMap[$QType]
    $bytes.AddRange([byte[]]@((($qcode -band 0xFF00) -shr 8), ($qcode -band 0x00FF)))

    # QCLASS = IN(1)
    $bytes.AddRange([byte[]]@(0x00,0x01))

    return ,([byte[]]$bytes)
}

# ------------------------------------------------------------------------
# DoH probe: POST then GET fallback; validate DNS response header (QR bit)
# ------------------------------------------------------------------------
function Test-DohTemplate {
    param(
        [string]$TemplateUrl,
        [string]$ProbeName = 'example.com'
    )
    if (-not $TemplateUrl) { return $false }

    # Prepare query bytes
    $q = New-DnsQueryBytes -Name $ProbeName -QType 'A'

    # HTTP client
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(7)

    # Helper to check DNS response header (QR flag set)
    function Test-DnsResponseHeader([byte[]]$resp) {
        if (-not $resp -or $resp.Length -lt 12) { return $false }
        # Flags are bytes 2..3 of header (0-based indexing); QR is high bit of that 16-bit field
        $flags = ($resp[2] -shl 8) -bor $resp[3]
        $isResponse = ($flags -band 0x8000) -ne 0
        return $isResponse
    }

    try {
        # 1) Try POST
        $content = New-Object System.Net.Http.ByteArrayContent($q)
        $content.Headers.ContentType = 'application/dns-message'
        $content.Headers.Add('Accept','application/dns-message')

        $resp = $client.PostAsync($TemplateUrl, $content).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode) {
            $bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            if (Test-DnsResponseHeader $bytes) {
                return $true
            }
        }
    } catch { }

    try {
        # 2) GET fallback: ?dns=<base64url(dns-message)>
        $b64 = [Convert]::ToBase64String($q)
        $b64url = $b64.TrimEnd('=').Replace('+','-').Replace('/','_')
        $sep = '?'
        if ($TemplateUrl.Contains('?')) { $sep = '&' }
        $url = "$TemplateUrl$sep" + "dns=$b64url"

        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $url)
        $req.Headers.Add('Accept','application/dns-message')
        $resp2 = $client.SendAsync($req).GetAwaiter().GetResult()
        if ($resp2.IsSuccessStatusCode) {
            $bytes2 = $resp2.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            if (Test-DnsResponseHeader $bytes2) {
                return $true
            }
        }
    } catch { }

    return $false
}

# ------------------------------------------------------------------------
# Windows: set Windows Adapter IPv4 DNS
# ------------------------------------------------------------------------
function Set-AdapterDnsIPv4 {
    param([ipaddress]$Dns1, [ipaddress]$Dns2)

    Write-Info "Applying adapter IPv4 DNS servers to active interfaces..."
    $rows = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch 'Loopback|Virtual|Tunneling|isatap|TAP|VPN' } | Select-Object -Unique InterfaceAlias, InterfaceIndex

    if (-not $rows -or $rows.Count -eq 0) {
        Write-Warn "  No suitable IPv4 DNS client interfaces found."
        return
    }

    $servers = @()
    if ($Dns1) { $servers += $Dns1.IPAddressToString }
    if ($Dns2) { $servers += $Dns2.IPAddressToString }

    if ($servers.Count -eq 0) {
        Write-Warn "  No DNS servers provided; nothing to apply."
        return
    }

    foreach ($a in $rows) {
        Write-Info ("  - {0} (Idx {1}) -> {2}" -f $a.InterfaceAlias, $a.InterfaceIndex, ($servers -join ', '))
        Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
        Write-OK "    Applied."
    }
}

# ------------------------------------------------------------------------
# Windows: register DNS DoH template (IP -> HTTPS template)
# ------------------------------------------------------------------------
function Register-DohTemplate {
    param([string]$ServerIP, [string]$Template)
    if (-not $ServerIP -or -not $Template) { return }

    $addCmd = Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    if ($addCmd) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $ServerIP -DohTemplate $Template -AutoUpgrade:$true -AllowFallbackToUdp:$true -ErrorAction Stop
            Write-OK ("  Registered DoH template: {0} -> {1}" -f $ServerIP, $Template)
        } catch {
            Write-Warn ("  Cmdlet for DoH template registration failed ({0}); trying netsh..." -f $_.Exception.Message)
            $args = @('dns','add','encryption', "server=$ServerIP", "dohtemplate=$Template", 'autoupgrade=yes', 'udpfallback=yes')
            & netsh @args | Out-Null
            if ($LASTEXITCODE -ne 0) {throw "netsh failed with exit code $LASTEXITCODE for $ServerIP -> $Template" }
            Write-OK ("  Registered DoH template via netsh: {0} -> {1}" -f $ServerIP, $Template)
        }
    } else {
        # Build args array for netsh call (PowerShell-safe quoting)
        $args = @('dns','add','encryption', "server=$ServerIP", "dohtemplate=$Template", 'autoupgrade=yes', 'udpfallback=yes')
        & netsh @args | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "netsh failed with exit code $LASTEXITCODE for $ServerIP -> $Template" }
        Write-OK ("  Registered DoH template via netsh: {0} -> {1}" -f $ServerIP, $Template)
    }
}

# ------------------------------------------------------------------------
# Windows: set Windows DoH policy (Windows Registry HKLM policy path)
# ------------------------------------------------------------------------
function Set-WindowsDohPolicy {
    param([WinDohPolicy]$WinPolicy)

    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }

        $v = $null
        switch ($WinPolicy) {
            'Off'     { $v = 0 }
            'Allow'   { $v = 1 }
            'Require' { $v = 2 }
            default   { return } # Unchanged -> do nothing
        }

        Set-ItemProperty -Path $path -Name "DoHPolicy" -Type DWord -Value $v -ErrorAction Stop
        Write-OK ("Windows DNS DoH policy set to {0} ({1})" -f $WinPolicy, $v)
    } catch {
        Write-Err ("Failed to set Windows DoH policy: {0}" -f $_.Exception.Message)
        throw
    }
}

# ------------------------------------------------------------------------
# Chrome (per-user Windows HKCU policy)
# ------------------------------------------------------------------------
function Set-ChromePolicy {
    param([TriState]$State, [string[]]$Templates)

    if ($State -eq [TriState]::Unchanged) { Write-Warn "Skipping Chrome (Unchanged)."; return }

    $base = "HKCU:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $base)) { New-Item -Path $base -Force -ErrorAction Stop | Out-Null }

    $templatesString = ($Templates | Where-Object { $_ }) -join ' '

    switch ($State) {
        'Enable' {
            if ($templatesString) {
                New-ItemProperty -Path $base -Name "DnsOverHttpsMode" -PropertyType String -Value "secure" -Force -ErrorAction Stop | Out-Null
                New-ItemProperty -Path $base -Name "DnsOverHttpsTemplates" -PropertyType String -Value $templatesString -Force -ErrorAction Stop | Out-Null
                Write-OK "Chrome DoH: secure; templates set (HKCU)."
            } else {
                New-ItemProperty -Path $base -Name "DnsOverHttpsMode" -PropertyType String -Value "automatic" -Force -ErrorAction Stop | Out-Null
                Remove-ItemProperty -Path $base -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
                Write-Warn "Chrome DoH: automatic (no templates provided)."
            }
        }
        'Disable' {
            New-ItemProperty -Path $base -Name "DnsOverHttpsMode" -PropertyType String -Value "off" -Force -ErrorAction Stop | Out-Null
            Remove-ItemProperty -Path $base -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
            Write-OK "Chrome DoH: disabled (HKCU)."
        }
    }
}

# ------------------------------------------------------------------------
# Firefox (per-user user.js)
# ------------------------------------------------------------------------
function Set-FirefoxDoh {
    param([TriState]$State, [string]$PrimaryTemplate, [string]$BootstrapIP)

    if ($State -eq [TriState]::Unchanged) { Write-Warn "Skipping Firefox (Unchanged)."; return }

    $profilesRoot = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (-not (Test-Path $profilesRoot)) { Write-Warn "Firefox profiles not found for current user."; return }

    $profiles = Get-ChildItem -Path $profilesRoot -Directory -ErrorAction SilentlyContinue
    if (-not $profiles -or $profiles.Count -eq 0) { Write-Warn "No Firefox profiles found."; return }

    Write-Info ("Configuring Firefox DoH for {0} profile(s)..." -f $profiles.Count)

    foreach ($p in $profiles) {
        $userJs = Join-Path $p.FullName "user.js"
        $existing = @()
        if (Test-Path $userJs) { $existing = Get-Content -LiteralPath $userJs -ErrorAction SilentlyContinue }
        $filtered = $existing | Where-Object {
            $_ -notmatch '^\s*user_pref\("network\.trr\.' -and $_ -notmatch '^\s*// DNS over HTTPS'
        }

        switch ($State) {
            'Enable' {
                $lines = @('user_pref("network.trr.mode", 2);')
                if ($PrimaryTemplate) {
                    $lines += ('user_pref("network.trr.uri", "{0}");' -f $PrimaryTemplate)
                } else {
                    $lines += '// DNS over HTTPS enabled, but no known DoH template for the chosen resolver'
                }
                if ($BootstrapIP) {
                    $lines += ('user_pref("network.trr.bootstrapAddress", "{0}");' -f $BootstrapIP)
                }
                $lines += ('// DNS over HTTPS configured')
                $out = $filtered + $lines
            }
            'Disable' {
                $lines = @(
                    'user_pref("network.trr.mode", 5);',
                    '// DNS over HTTPS disabled by policy'
                )
                $out = $filtered + $lines
            }
        }

        try {
            $out | Out-File -LiteralPath $userJs -Encoding UTF8
            Write-OK ("  {0}: user.js updated" -f $p.Name)
        } catch {
            Write-Warn ("  {0}: failed to update user.js: {1}" -f $p.Name, $_.Exception.Message)
        }
    }
}

# ------------------------------------------------------------------------
# BEGIN EXECUTION
# ------------------------------------------------------------------------
Write-Headline "=== DNS over HTTPS Configuration ==="

# Compute the candidate IPs that we will consider for template registration / checks
# If you intend to change adapter DNS in this run, we prefer those provided IPs.
$existingIPs = Get-CurrentAdapterDnsIPv4
$candidateIPs = @()
if ($ApplyAdapterDNS -and ($PSBoundParameters.ContainsKey('PrimaryDNS') -or $PSBoundParameters.ContainsKey('SecondaryDNS'))) {
    if ($PrimaryDNS)   { $candidateIPs += $PrimaryDNS.IPAddressToString }
    if ($SecondaryDNS) { $candidateIPs += $SecondaryDNS.IPAddressToString }
} else {
    $candidateIPs = $existingIPs
}
$candidateIPs = ($candidateIPs | Where-Object { $_ } | Select-Object -Unique)

Write-Info ("Existing  DNS IPs: {0}" -f ($(if ($existingIPs) { $existingIPs -join ', ' } else { '(none)' })))
Write-Info ("Candidate DNS IPs: {0}" -f ($(if ($candidateIPs) { $candidateIPs -join ', ' } else { '(none)' })))

# Build a deduped list of DoH templates to consider for browsers
$knownTemplates = @()
foreach ($ip in $candidateIPs) {
    if ($dnsToDohMap.ContainsKey($ip)) { $knownTemplates += $dnsToDohMap[$ip] }
}
$knownTemplates = $knownTemplates | Select-Object -Unique

# ------------------------------------------------------------------------
# Optionally apply adapter DNS (independent of WindowsDoH)
# ------------------------------------------------------------------------
if ($ApplyAdapterDNS) {
    try {
        if (-not $PrimaryDNS -and -not $SecondaryDNS) {
            Write-Warn "ApplyAdapterDNS requested but no DNS IPs were supplied; skipping adapter DNS changes."
        } else {
            Set-AdapterDnsIPv4 -Dns1 $PrimaryDNS -Dns2 $SecondaryDNS
        }
    } catch {
        Write-Err ("Failed to set adapter DNS: {0}" -f $_.Exception.Message)
        $script:HadError = $true
    }
}

# ------------------------------------------------------------------------
# WINDOWS: DoH configuration (requires Admin)
# ------------------------------------------------------------------------
try {
    if ($WindowsDoH -ne [TriState]::Unchanged) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
                   IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

        if (-not $isAdmin) {
            Write-Err "WindowsDoH requested, but the script is not running elevated. Skipping Windows."
        } else {
            Write-Headline "Windows: preflight checks"

            # 1) Plain DNS liveness (TCP/53) — at least one candidate should respond, unless you intend Require with known good DoH
            $plainOK = $false
            foreach ($ip in $candidateIPs) {
                $ok = Test-PlainDnsTcp -ServerIP $ip
                Write-Info ("  TCP/53 to {0}: {1}" -f $ip, ($(if ($ok) { 'OK' } else { 'Fail' })))
                if ($ok) { $plainOK = $true }
            }

            # 2) Register known templates for candidate IPs
            $templatesForWindows = @()
            foreach ($ip in $candidateIPs) {
                $tpl = $dnsToDohMap[$ip]
                if ($tpl) {
                    Register-DohTemplate -ServerIP $ip -Template $tpl
                    $templatesForWindows += $tpl
                } else {
                    Write-Warn ("  No known DoH template for {0}. You can still use Allow (fallback to plaintext). Require will be blocked." -f $ip)
                }
            }
            $templatesForWindows = $templatesForWindows | Select-Object -Unique

            # Determine effective policy we aim for
            $requestedPolicy = $WindowsPolicy
            if ($WindowsDoH -eq [TriState]::Enable -and $requestedPolicy -eq [WinDohPolicy]::Unchanged) {
                $requestedPolicy = [WinDohPolicy]::Allow  # safe default
            }
            if ($WindowsDoH -eq [TriState]::Disable) {
                $requestedPolicy = [WinDohPolicy]::Off
            }

            # 3) If Require is requested, we must have known templates and they must pass 443 + DoH probe
            $canRequire = $true
            if ($requestedPolicy -eq [WinDohPolicy]::Require) {
                if (-not $templatesForWindows -or $templatesForWindows.Count -eq 0) {
                    $canRequire = $false
                    Write-Err "Cannot set Require: no known DoH templates for candidate IPs."
                } else {
                    foreach ($tpl in $templatesForWindows) {
                        $dohHost = Get-DohHost -Template $tpl
                        $h443 = Test-Tcp443 -Host $host
                        Write-Info ("  443 to {0}: {1}" -f $dohHost, ($(if ($h443) { 'OK' } else { 'Fail' })))
                        if (-not $h443) { $canRequire = $false }

                        $probe = $false
                        if ($h443) {
                            $probe = Test-DohTemplate -TemplateUrl $tpl -ProbeName 'example.com'
                            Write-Info ("  DoH probe {0}: {1}" -f $tpl, ($(if ($probe) { 'OK' } else { 'Fail' })))
                            if (-not $probe) { $canRequire = $false }
                        }
                    }
                }
            }

            # 4) Apply policy: Off / Allow / Require (with two-phase for Require)
            switch ($requestedPolicy) {
                'Off' {
                    Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Off)
                }
                'Allow' {
                    # We prefer to have at least one plain DNS OK, but still apply Allow even if plaintext is down,
                    # since DoH may still succeed.
                    Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Allow)
                    # Flush DNS to apply quickly
                    Write-Info "Flushing DNS cache..."
                    ipconfig /flushdns | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warn "DNS cache flush using ipconfig /flushdns fail, exited with code $LASTEXITCODE." 
                    } else {
                        Write-OK "DNS cache flushed using ipconfig /flushdns"
                    }

                    # Smoke test OS resolution
                    try {
                        $res = Resolve-DnsName -Name "example.com" -Type A -ErrorAction Stop
                        Write-OK "OS resolver test (example.com): OK"
                    } catch {
                        Write-Warn "OS resolver test failed after Allow; name resolution may be impaired."
                    }
                }
                'Require' {
                    if (-not $canRequire) {
                        Write-Err "Blocking Require due to failing preflight checks. Applying Allow for safety."
                        Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Allow)
                    } else {
                        # Phase 1: Allow
                        Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Allow)
                        Write-Info "Flushing DNS cache using ipconfig /flushdns ..."
                        ipconfig /flushdns | Out-Null
                        if ($LASTEXITCODE -ne 0) {
                            Write-Warn "DNS cache flush using ipconfig /flushdns fail, exited with code $LASTEXITCODE."
                        } else {
                            Write-OK "DNS cache flushed using ipconfig /flushdns"
                        }

                        # Verify OS resolver works under Allow
                        $allowOK = $false
                        try {
                            $res = Resolve-DnsName -Name "example.com" -Type A -ErrorAction Stop
                            $allowOK = $true
                            Write-OK "OS resolver test (example.com) under Allow: OK"
                        } catch {
                            Write-Err "OS resolver test failed under Allow; refusing to promote Allow to Require."
                        }

                        # Phase 2: Promote to Require if Allow succeeded
                        if ($allowOK) {
                            Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Require)
                            Write-OK "Promoted to Require."
                        } else {
                            Write-Warn "Staying on Allow due to failed test."
                        }
                    }
                }
                default {
                    Write-Warn "WindowsDoH=Enable but WindowsPolicy=Unchanged; applied Allow as a safe default."
                    Set-WindowsDohPolicy -WinPolicy ([WinDohPolicy]::Allow)
                }
            }
        }
    } else {
        Write-Warn "Skipping Windows (Unchanged)."
    }
} catch {
    Write-Err ("Windows configuration error: {0}" -f $_.Exception.Message)
    $script:HadError = $true
}

# ------------------------------------------------------------------------
# CHROME: per-user policy (HKCU)
# ------------------------------------------------------------------------
try {
    if ($ChromeDoH -ne [TriState]::Unchanged) {
        # Build templates for Chrome: prefer those associated with candidate IPs (if any)
        Set-ChromePolicy -State $ChromeDoH -Templates $knownTemplates
    } else {
        Write-Warn "Skipping Chrome (Unchanged)."
    }
} catch {
    Write-Err ("Chrome configuration error: {0}" -f $_.Exception.Message)
    $script:HadError = $true
}

# ------------------------------------------------------------------------
# FIREFOX: per-user user.js
# ------------------------------------------------------------------------
try {
    if ($FirefoxDoH -ne [TriState]::Unchanged) {
        # Firefox takes a single primary URI + optional bootstrapAddress
        $primaryTpl = $null
        $bootstrap  = $null
        if ($knownTemplates -and $knownTemplates.Count -gt 0) {
            $primaryTpl = $knownTemplates[0]
            # if our candidate pool has a single dominant IP, use it as bootstrap
            if ($candidateIPs -and $candidateIPs.Count -gt 0) { $bootstrap = $candidateIPs[0] }
        }

        Set-FirefoxDoh -State $FirefoxDoH -PrimaryTemplate $primaryTpl -BootstrapIP $bootstrap
    } else {
        Write-Warn "Skipping Firefox (Unchanged)."
    }
} catch {
    Write-Err ("Firefox configuration error: {0}" -f $_.Exception.Message)
    $script:HadError = $true
}

# ------------------------------------------------------------------------
# Summary & final smoke tests
# ------------------------------------------------------------------------
Write-Host ""
Write-Headline "=== Summary ==="
Write-Info ("Windows:  {0} (Policy: {1})" -f $WindowsDoH, $WindowsPolicy)
Write-Info ("Chrome:   {0}" -f $ChromeDoH)
Write-Info ("Firefox:  {0}" -f $FirefoxDoH)

# Show Windows DoH registrations if available
try {
    $cmd = Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    if ($cmd) {
        $doh = Get-DnsClientDohServerAddress -ErrorAction Stop
        if ($doh) {
            Write-Info "Registered Windows DoH servers:"
            $doh | ForEach-Object {
                Write-Info ("  - {0} -> {1} (AutoUpgrade={2}, UdpFallback={3})" -f $_.ServerAddress, $_.DohTemplate, $_.AutoUpgrade, $_.AllowFallbackToUdp)
            }
        }
    } else {
        Write-Warn "Get-DnsClientDohServerAddress not available (older OS). Use 'netsh dns show encryption'."
    }
} catch {
    Write-Warn ("Could not list Windows DoH registrations: {0}" -f $_.Exception.Message)
}

Write-Host ""
Write-Headline "=== DNS Smoke Tests (not proof of DoH by themselves) ==="
try {
    $names = @('example.com','cloudflare.com','quad9.net')
    foreach ($n in $names) {
        $ok = $false
        try { $res = Resolve-DnsName -Name $n -Type A -ErrorAction Stop; $ok = $true } catch {}
        if ($ok) { Write-OK   ("  {0}: OK" -f $n) } else { Write-Warn ("  {0}: Failed" -f $n) }
    }
} catch {
    Write-Warn ("Smoke tests failed: {0}" -f $_.Exception.Message)
}

Write-Host ""
if ($script:HadError) {
    Write-Warn "Completed with warnings/errors (see messages above)."
} else {
    Write-OK "Configuration complete. Restart browsers for changes to take effect."
}
