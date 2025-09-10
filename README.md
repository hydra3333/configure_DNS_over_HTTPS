# Script to (re)Set DoH (DNS over HTTPS) and DNS IP addresses

![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey) ![License](https://img.shields.io/badge/license-AGPL--3.0-green)

A PowerShell script to (re)configure DNS-over-HTTPS (DoH) and DNS server IPs for:

- **Windows 11** (OS resolver; requires Administrator privileges)
- **Chrome** (per-user, in Windows Registry HKCU policy)
- **Firefox** (per-user, in file `user.js` in each profile)

It’s intentionally **careful and test-first**: it checks reachability and does a real DoH probe before enforcing stricter settings, to help avoid breaking name resolution.
You can also optionally change the Windows adapter’s DNS IPs — just remember any **original** IPs if you plan to revert to later.

> **Supported resolvers:** only a subset are recognized out of the box (see the IP -> DoH template map in the script). You can extend that map as you verify more providers.

---

## What this script does

- **Tri-state per target**
  - `WindowsDoH` : `Unchanged | Enable | Disable` (Windows, needs Admin privilege)
  - `ChromeDoH`  : `Unchanged | Enable | Disable` (per-user Windows Registry HKCU policy)
  - `FirefoxDoH` : `Unchanged | Enable | Disable` (per-user file `user.js`)

- **Windows-specific policy**
  - `WindowsPolicy` : `Unchanged | Off | Allow | Require`  
    When enabling and policy = **Require**, the script first applies **Allow**, verifies resolution, then promotes to **Require** **only if safe**.
  - `Unchanged` : don't change the current setting
  - `Off`     : turn of DNS over HTTPS in Windows
  - `Allow`   : turn on DNS over HTTPS in Windows with fallback to plain text DNS if DoH fails
  - `Require` : turn of DNS over HTTPS in Windows with no fallback DNS

- **'Windows Adapter DNS' IPs are *not* changed** unless you explicitly ask:
  - Use `-ApplyAdapterDNS` **and** provide `-PrimaryDNS/-SecondaryDNS` to set IPv4 DNS on active adapters.
  - Otherwise, the 'Windows Adapter DNS's IPs stay as-is and this script only registers DoH templates and sets policy.

- **Safety checks (always on)**
  - **TCP/53** liveness against candidate DNS IPs (plaintext fallback viability)
  - **TCP/443** reachability for each DoH hostname
  - **Real DoH probe** (RFC 8484): sends a tiny `application/dns-message` query and verifies a valid DNS response per the standard
  - **Two-phase Windows `Require` policy apply**: `Allow -> test -> Require (if passes Allow)`
  - **Blocks `Require`** if a template is unknown or any probe fails

---

## Key concepts (quick primer)

- **Windows DoH** uses the **Windows Adapter’s DNS IPs** (ie the 'normal' Windows DNS IP Addresses) as the resolver identity. You register a **DoH template URL** for each IP (IP -> HTTPS template) and then set policy:
  - `Off` = plaintext only
  - `Allow` = prefer DoH, **fallback to plain text allowed**
  - `Require` = DoH only, **no fallback, only DNS over HTTPS allowed**

- **Browsers**
  - With browser DoH **enabled**, Chrome/Firefox talk **directly** to their specified DoH endpoints.
  - With browser DoH **disabled**, they defer to the **OS resolver** (which may still use DoH if Windows policy allows it).

---

## Defaults

- **Safe mode:** always on (no switch to disable).
- **No default DNS IPs applied.** To change Windows Adapter DNS, use:

```powershell
-ApplyAdapterDNS -PrimaryDNS <ip> -SecondaryDNS <ip>
```

---

## Examples

> Replace the path with your actual script filename (e.g., `.\configure_DNS_over_HTTPS.ps1`).

```powershell
# 1) Windows DoH Enable using CURRENT adapter DNS (no change of adapter IPs):
#    Register templates for recognized current DNS IPs; set Allow; test; promote to Require.
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
  -File ".\configure_DNS_over_HTTPS.ps1" `
  -WindowsDoH Enable -WindowsPolicy Require
```

```powershell
# 2) Firefox DoH only (per-user), leave Windows unchanged:
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
  -File ".\configure_DNS_over_HTTPS.ps1" `
  -FirefoxDoH Enable
```

```powershell
# 3) Chrome DoH only (per-user), leave Windows unchanged:
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
  -File ".\configure_DNS_over_HTTPS.ps1" `
  -ChromeDoH Enable
```

```powershell
# 4) Change adapter DNS to Cloudflare + Quad9 (WITHOUT touching Windows DoH policy):
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
  -File ".\configure_DNS_over_HTTPS.ps1" `
  -ApplyAdapterDNS -PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9
```

```powershell
# 5) Windows DoH Disable (policy Off), keep adapter DNS as-is:
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden `
  -File ".\configure_DNS_over_HTTPS.ps1" `
  -WindowsDoH Disable
```

---

## Parameters (overview)

| Parameter         | Type/Values                         | Scope        | Notes |
|-------------------|-------------------------------------|--------------|-------|
| `WindowsDoH`      | `Unchanged \| Enable \| Disable`    | OS (Admin)   | Controls Windows DoH behavior. |
| `WindowsPolicy`   | `Unchanged \| Off \| Allow \| Require` | OS (Admin) | Effective when `WindowsDoH=Enable/Disable`. Safe flow enforces **Allow->test->Require**. |
| `ChromeDoH`       | `Unchanged \| Enable \| Disable`    | User (HKCU)  | Sets per-user Chrome policy; `Enable` uses known templates when available. |
| `FirefoxDoH`      | `Unchanged \| Enable \| Disable`    | User         | Writes `user.js` in each current user profile; TRR mode 2 (DoH-first) by default. |
| `ApplyAdapterDNS` | switch                              | OS (Admin)   | Only sets adapter DNS if **also** given `PrimaryDNS`/`SecondaryDNS`. |
| `PrimaryDNS`      | IPv4                                | OS (Admin)   | Used **only** with `-ApplyAdapterDNS`; otherwise ignored. |
| `SecondaryDNS`    | IPv4                                | OS (Admin)   | Used **only** with `-ApplyAdapterDNS`. |

> **Admin requirement:** Windows changes (policy, template registration, adapter DNS) require elevation. Chrome/Firefox changes are per-user and do **not** require admin.

---

## Safety notes

- **Require is strict**: name resolution will fail if DoH endpoints aren’t reachable. The script prevents applying `Require` unless endpoints **pass** TLS and **DoH probe** checks.
- **No silent DNS IP changes**: the script **never** changes adapter DNS unless you pass `-ApplyAdapterDNS` with explicit IPs.
- **Rollback**: to return to plaintext, disable browser DoH and set Windows policy to `Off`. To restore previous DNS IPs, reapply your original adapter DNS values.

---

## Extending resolver support

Add entries to the in-script **IP -> DoH template** map as you verify secure DNS providers, eg:

```
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
```

If a DNS resolver’s DoH endpoint isn’t known, the script will still allow **Allow** (ie prefers DoH; can fall back to plaintext) but will **block Require** to avoid bricking DNS.

---

## License

AGPL-3.0. See `LICENSE` for details.
