# DNS over HTTPS (DoH) Configuration Script — Change Specification (PowerShell 5.1)

**Version:** 1.2.4 — 2025‑09‑11 (Australia/Adelaide)  
**File tag:** 00100‑SPEC‑FOR‑CHANGE

> **What changed in v1.2 (minimal edits):**
> 1) Keep unified policy knob as **`-DoHPolicy`** (Off/Allow/Require).  
> 2) **Chrome & Firefox now write provider templates even in Allow** (when known) for determinism; Require remains gated and degrades to Allow if templates/probe are unavailable.  
> 3) Updated **§2.5** table and **§7 items 7 & 8** to reflect this. Everything else remains as in v1.1.
> **What changed in v1.2.1, 1.2.2, 1.2.3 (minimal edits):**
> 1) Fix spelling errors, wording, clarify a couple of minor things
> **What changed in v1.2.4:**
> 1) clarify mandatory always-safe behaviours
---

**Goal:** produce a stable, PowerShell 5.1–compatible script that can safely configure DoH across **Windows 11 (OS resolver)**, **Chrome (HKCU policy)**, and **Firefox (user.js per profile)**, while **never breaking name resolution** and **always proving what worked**.

The script must:

* Implement **Unified DoH semantics per target** (single user intent: Off / Allow / Require -> target-specific knobs).
* Maintain Mandatory **Always-safe** behaviors (preflight tests, staged changes, verified outcomes, rollback/degrade when not safe) etc.
* Allow **independent control** of **adapter DNS IPs** and **DoH templates** vs. **DoH policy** for each target.
* Provide **deterministic, rich diagnostics** via a single switch (without changing behavior).
* Remain **PowerShell 5.1–safe** and robust (no PS7-only syntax, no `$Host` collisions, try/catch around OS mutations).

The “nearly working” version will be the **initial base version** for changes to be build upon. 

This specification defines what to add/change adn what stance to adopt eg "Always-Safe".

---

## 1) Command-line Interface (CLI)

### 1.1 Parameters (one `param(...)` block)

* `-DoHPolicy` : `Unchanged|Off|Allow|Require` (the **single, unified** DoH intent applied to any target whose *per-target* DoH toggle is `Enable`)
* `-WindowsDoH` : `Unchanged|Enable|Disable` (TriState for OS resolver policy)
* `-ChromeDoH`  : `Unchanged|Enable|Disable` (TriState)
* `-FirefoxDoH` : `Unchanged|Enable|Disable` (TriState)
* `-ApplyAdapterDNS` (switch): **only** change NIC DNS when this is present **and** at least one IP is supplied
* `-PrimaryDNS` : `ipaddress` (optional)
* `-SecondaryDNS` : `ipaddress` (optional)
* `-PrintDiagnostics` (switch): **controls verbosity only** (printing extra diagnostics); **never changes behavior**

> Notes  
> • Keep **enums** (TriState, DoHPolicy) **above** any usage and **once only**.  
> • Ensure there is **one** param block.  
> • All parameter names are case-insensitive; avoid `$Host` / `$host` anywhere.

---

## 2) Unified DoH Semantics (per target)

Single user meaning, mapped to each product’s native knobs.

### 2.1 Windows 11 (OS resolver)

* **Disable** -> `DoHPolicy=Off (0)` -> plaintext DNS only.
* **Allow**   -> `DoHPolicy=Allow (1)` -> prefer DoH **if** template exists; fallback to plaintext.
* **Require** -> `DoHPolicy=Require (2)` -> DoH only (no plaintext fallback). **Only set if safe** (see §4).

**Also**: DoH **template registration** is a separate concern (IP -> template).

* Preferred:  
  `Add-DnsClientDohServerAddress -ServerAddress <IP> -DohTemplate <URL> -AutoUpgrade:$true -AllowFallbackToUdp:$true`
* Fallback:  
  `netsh dns add encryption server=<IP> dohtemplate=<URL> autoupgrade=yes udpfallback=yes`
* Registration must be **idempotent**; print **before/after** and report **“already registered”** when unchanged.

### 2.2 Chrome (HKCU policy)

* **Disable** -> `DnsOverHttpsMode=off` (Chrome uses OS resolver).
* **Allow**   -> `DnsOverHttpsMode=automatic`.  
  **Always set `DnsOverHttpsTemplates` when a known template exists** (for determinism). If none known, leave templates empty; Chrome may still auto-upgrade.
* **Require** -> `DnsOverHttpsMode=secure` **and** `DnsOverHttpsTemplates="<space-separated templates>"`.  
  **Require is gated** (see §4.5): if **no known template** or probe fails, **degrade to Allow** (`automatic`; templates left empty) and warn clearly.

### 2.3 Firefox (per-profile user.js)

* **Disable** -> `network.trr.mode=5` (use OS resolver).
* **Allow**   -> `network.trr.mode=2` (TRR-first; fallback allowed).  
  **Always set `network.trr.uri` when a known template exists** (and `network.trr.bootstrapAddress` when appropriate) for determinism.
* **Require** -> `network.trr.mode=3` (TRR-only; no plaintext fallback) **and** `network.trr.uri="<template>"`; optionally `network.trr.bootstrapAddress="<ip>"`.  
  **Require is gated** (see §4.5): if **no known template** or probe fails, **degrade to Allow**: `mode=2` (keep `trr.uri` if known) and warn.

**Policy note**: We do **not** use `policies.json` or registry enterprise policy. We **only** write `user.js` in each current user profile.

### 2.4 High-level intent (what the user chooses)

> **Unified intent -> per-target knobs:** Off = plaintext; Allow = prefer DoH with fallback; Require = DoH only (with safety rails).

| Target         | (A) **Off**       | (B) **Allow / TRR-first / Automatic** | (C) **Require / TRR-only / Secure** |
| -------------- | ----------------- | ------------------------------------- | ----------------------------------- |
| **Windows 11** | Plaintext only    | Prefer DoH; fallback to plaintext     | DoH only (templates must exist)     |
| **Chrome**     | DoH disabled      | Try DoH; may fallback (templates set when known for determinism) | DoH only (set templates)            |
| **Firefox**    | `mode=5` (OS DNS) | `mode=2` (TRR-first) (template set when known) | `mode=3` (TRR-only) + `trr.uri`     |

### 2.5 Exact knobs to set (what the script applies)

| Target                                 | (A) **Off**                                                                                  | (B) **Allow / TRR-first / Automatic**                                                                                                            | (C) **Require / TRR-only / Secure**                                                                                                                                                 |
| -------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Windows 11 – Policy**                | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy = 0` (**Off**)              | `…\DoHPolicy = 1` (**Allow**)                                                                                                                    | `…\DoHPolicy = 2` (**Require**) *(only if safe checks pass; else fall back to 1)*                                                                                                    |
| **Windows 11 – Template registration** | No change required                                                                           | **Register** IP->template for each candidate IP (**idempotent; print Before/After; “already registered” when unchanged**)                         | **Register** IP->template for each candidate IP (required); block Require if unknown or probes fail                                                                                   |
| **Chrome (HKCU Policy)**               | `DnsOverHttpsMode=off`; **remove** `DnsOverHttpsTemplates`                                   | `DnsOverHttpsMode=automatic`; **if a known template exists, set** `DnsOverHttpsTemplates="<space-separated templates>"`; else leave empty        | If known template: `DnsOverHttpsMode=secure` **and** `DnsOverHttpsTemplates="<space-separated templates>"`; if none known -> **degrade to Allow** (`automatic`, no templates) + warn |
| **Firefox (user.js per profile)**      | `network.trr.mode=5` (use OS DNS); **remove** `network.trr.uri`/`bootstrapAddress` we manage | `network.trr.mode=2`; **if a known template exists, set** `network.trr.uri="<template>"` (+ `bootstrapAddress` where appropriate) for determinism | `network.trr.mode=3` **and** `network.trr.uri="<template>"`; optionally `bootstrapAddress`; if **no known template/probe fails** -> **degrade to `mode=2`** (keep uri if known) + warn |

**Notes / safety rails (non-diagnostic):**

* **Require gating (all targets):** Only enforce “Require/Secure/TRR-only” when a **known, reachable DoH endpoint** exists and a **real DoH probe** passes (RFC 8484 `application/dns-message`, POST first then GET fallback; TLS SystemDefault then one fallback to TLS 1.2; restore original TLS).
* **Windows promotion sequence:** Apply **Allow (1)** -> flush DNS -> **OS resolve test** -> then **Require (2)**; if test fails, **stay on Allow**.
* **Templates vs. DNS IPs:** Template registration (IP->template) is **independent** of changing adapter DNS IPs. Only change NIC DNS when `-ApplyAdapterDNS` **and** at least one of `-PrimaryDNS/-SecondaryDNS` is supplied.
* **Idempotent & auditable:** For every change, print **Before / After**; if unchanged, say “already registered” or “no change”.
* **Diagnostics switch:** `-PrintDiagnostics` **only** increases verbosity (richer `Test-NetConnection`, registry reads, DoH probe hex/header, Firefox canary/policy checks, Chrome policy readback). **All tests always run** regardless of verbosity.

---

## 3) Independent controls (DNS IPs, templates, policy)

* **Adapter DNS (IPv4) changes** happen **only** when `-ApplyAdapterDNS` is present **and** at least one of `-PrimaryDNS`/`-SecondaryDNS` is supplied.
  * Without `-ApplyAdapterDNS`, NIC DNS values **remain unchanged**.
* **DoH template registration** must be performed based on **candidate IPs** (either the provided IPs when applying adapter DNS this run, or the current adapter DNS IPs if not changing them).
* **DoH policy** (Windows / Chrome / Firefox) must be set **independently** from adapter DNS changes and template registration.
  * I.e., you can register templates without changing NIC DNS; you can also change NIC DNS without changing DoH policy.

---

## 4) Mandatory Always-Safe behaviors

### 4.1 Always 

* Always-safe behaviors include rigorous preflight tests, staged changes, verified outcomes, rollback/degrade when not safe
* All checks **always run**
* Ensure failures of actions/tests for critical elements are able to be rolled back (eg windows DoH to `secure`)
* Ensure checking of all return statuses - eg from cmdlets and external calls such as netsh etc and POST/GET etc - and actioning of them appropiately
* Ensure try/catch for all actions and all tests eg all cmdlets and external calls such as netsh etc and POST/GET and probes etc
* Ensure confirmation-it-worked tests following actions whenever reasonably possible 

* Ensure ungated **before/after** prints uniformly to facilitate well-informed progress tracking (eg before/after changes, action name/description and results, test name/description and results, etc)
* Use `-PrintDiagnostics` commandline switch gate enabling printing of additional richer diagnostic level information (including dumping objects) everywhere (eg info relating to Windows, Chrome, Firefox, DoH probe, and all other tests/checks/actions) and without gating any actions/behavior.

### 4.2 Preflight (before setting **Windows Require**) examples include

For each candidate Windows DoH template:

1. **TCP/443 reachability** to the DoH host.
2. **DoH probe** (**RFC 8484 application/dns-message**):
   * **POST** first;
   * If POST fails or returns invalid DNS, try **GET** (`?dns=<base64url>`).
   * **TLS**: use **SystemDefault** first; if it fails, **retry once with TLS 1.2**; after the probe, **restore original TLS** setting.
   * Validate: HTTP 200, `Content-Type: application/dns-message`, DNS header with **QR** bit set, sensible opcode/rcode.
3. If any required probe fails -> **block Require** and apply **Allow** instead (with clear warning).

### 4.3 Two-phase Windows promotion (Require) examples include

* Set **Allow** -> `ipconfig /flushdns` -> test `Resolve-DnsName example.com`.
* If OS resolver passes, **promote** to **Require**; else **remain** on Allow with warning.
* **Read back** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy` and print: **“Effective Windows DoH policy: <mode> (<DWORD>)”**.

### 4.4 Chrome Require guard (gated) examples include

* **Gating conditions (both required):** *(a)* at least one known template exists; *(b)* a DoH probe succeeds (§4.2).  
* If gated conditions hold -> set `secure` **and** templates.  
* If either fails -> degrade to Allow: set automatic and if a known template exists, keep/set DnsOverHttpsTemplates (else leave empty); warn.

### 4.5 Firefox Require guard (gated) examples include

* **Gating conditions (both required):** *(a)* at least one known template exists; *(b)* a DoH probe succeeds (§4.2).  
* If gated conditions hold -> set `mode=3` **and** `trr.uri` (plus optional `bootstrapAddress`).  
* If either fails -> **degrade to Allow**: set `mode=2` (keep `trr.uri` if known) and **warn**.

### 4.6 Adapter DNS changes (when requested) examples include

* For each active IPv4 interface: print **Before** -> apply -> print **After** (server list).
* Wrap in `try/catch`; error should not stop other targets’ configuration.

---

## 5) Diagnostics & Logging

### 5.1 Behavior vs. verbosity

* **All checks always run**; `-PrintDiagnostics` only increases what we print to assist with debugging.
* When `-PrintDiagnostics` is present, print **rich details**; without it, print well-informed progress tracking (eg before/after changes, action name/description and results, test name/description and results, etc)

### 5.2 What to print (concise vs. diagnostic)

**Always print** (concise):

* **Before/After** for Windows adapter DNS, DoH template registration, and DoH policy values.
* **Windows Require gating** results (per-template):
  * `443 to <host>: OK/Fail`
  * `DoH probe <template>: OK/Fail`
* **OS smoke test** results (Resolve-DnsName for 2–3 domains).
* **Chrome**: final `DnsOverHttpsMode` and whether templates were set.
* **Firefox**: profile(s) updated and the `trr.mode` chosen; mention `trr.uri` if set.

**When `-PrintDiagnostics` is set**, print additional details over and above what is normally printed for every action and test (tests always run whether or not `-PrintDiagnostics` is set, per 'Always safe' behaviour) :

* **Windows**:
  * For `Test-NetConnection` 443 checks: full object dumps or key properties (RemoteAddress, TcpTestSucceeded).
  * For template registration: `Get-DnsClientDohServerAddress` and/or `netsh dns show encryption`.
  * Registry paths and policy DWORD values before/after.

* **DoH probe**:
  * POST/GET attempt sequence, HTTP status, content type, byte length,
  * Short hex preview of first bytes,
  * Parsed DNS header fields: ID, Flags, QR, RCODE (and reason if invalid),
  * TLS notes (attempts, fallback, restored setting).

* **Firefox**:
  * **Canary test (`use-application-dns.net`) — definition & method**
    * **What it is:** A special “opt-out” domain used by networks to signal that **automatic** DoH should be disabled. If the **system resolver** can resolve `use-application-dns.net` to any A/AAAA record, Firefox treats that as a **canary active** signal and (for automatic/TRR-first rollouts) may disable DoH. If it **does not resolve** (NXDOMAIN/timeout), the canary is **inactive** and automatic DoH is allowed.
    * **How we test:** Always perform a classic lookup via the OS resolver: `Resolve-DnsName use-application-dns.net -Type A,AAAA` (catch errors).
      * **If one or more A/AAAA records are returned:** report **“Canary active”** and list the IPs.
      * **If NXDOMAIN/SERVFAIL/timeout:** report **“Canary inactive”**.
    * **How to interpret it:** Explicit `network.trr.mode` settings **override** canary; enterprise policy (if present) **overrides** prefs regardless of canary.
    * **What we print:**
      * Concise: `Firefox canary: Active (A: <list> / AAAA: <list>)` or `Firefox canary: Inactive (NXDOMAIN/timeout)`.
      * With `-PrintDiagnostics`: include resolver used (OS), record types, TTLs, and any resolution errors.
  * Policy presence (HKLM/HKCU keys) and `policies.json` if present (path and exists). **If policy is active, print a clear “policy override” warning (user.js may be ignored).**
  * Each profile path touched; what entries written/overwritten in `user.js`.

* **Chrome**:
  * **HKCU** policy final values as read back (mode, templates string).

> Implementation note: Avoid `-InformationLevel Quiet` when `-PrintDiagnostics` is on; capture more detail.

---

## 6) Data & Mappings

### 6.1 Candidate IPs

* If `-ApplyAdapterDNS` **and** at least one of `-PrimaryDNS/-SecondaryDNS` was provided: **Candidates** = those provided IPs (deduped).
* Else: **Candidates** = current adapter IPv4 DNS IPs (deduped).

### 6.2 Known DoH map (IPv4 -> template)

Maintain a dictionary of common resolvers (Aussie Broadband, Cloudflare standard/security/family, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing, etc.). Keep the **provider label mapping** alongside this table for use in the summary.

* Used to:
  * Register Windows templates,
  * Provide templates for Chrome Allow/Require and Firefox Allow/Require,
  * Label providers in the summary.
* If an IP is unknown:
  * Warn loudly;
  * Windows Allow is still okay;
  * Block Windows Require;
  * Chrome Require falls back to Allow;
  * Firefox Require falls back to Allow.

---

## 7) Order of Operations

1. **Banner** + echo intended actions (target modes, whether adapter DNS will be applied).
2. **Discover existing state**:
   * Current adapter DNS servers (IPv4, per active interface),
   * Existing DoH registrations (cmdlet or `netsh`),
   * Effective Windows DoH policy (registry).
3. **Compute candidate IPs** (per §6.1).
4. **Adapter DNS (if requested)**:
   * For each active interface: print Before, apply, After; handle errors per-interface.
5. **Windows DoH template registration** (for each candidate IP with known template):
   * If absent -> register (cmdlet preferred; `netsh` fallback). Print Before/After.
6. **Windows DoH policy**:
   * If `WindowsDoH=Disable` -> set Off (0).
   * If `WindowsDoH=Enable` and **`DoHPolicy`**:
     * If `Require`:
       * Run preflight per §4.2; if any failure -> **Apply Allow** (1) and warn.
       * If preflight OK: **Allow -> flush -> OS resolve test -> Require**; if OS resolve fails after Allow, remain on Allow.
     * If `Allow`: set Allow (1), flush, smoke test OS.
     * If `Off`: set Off (0).
   * If `WindowsDoH=Enable` and `DoHPolicy=Unchanged`: set **Allow** as safe default (print that choice).
7. **Chrome DoH**:
   * If `ChromeDoH=Disable` -> set `DnsOverHttpsMode=off` and **clear** `DnsOverHttpsTemplates`.
   * If `ChromeDoH=Enable`:
     * If `DoHPolicy=Off` -> set `off` and **clear** templates.
     * If `DoHPolicy=Allow` -> set `automatic`; **always set `DnsOverHttpsTemplates` when a known template exists** for determinism; else leave templates empty.
     * If `DoHPolicy=Require` ->
       * If a **known template** exists, set `secure` **and** `DnsOverHttpsTemplates`.
       * If none known, **degrade to Allow**: set `automatic` (no templates) and **warn** clearly.
     * If `DoHPolicy=Unchanged` -> set `automatic` as a safe default and **(when known)** write templates for determinism; print that this is the safe default.
   * **Read back** and print final `DnsOverHttpsMode` and `DnsOverHttpsTemplates` from **HKCU**.
8. **Firefox DoH**:
   * Enumerate profiles; for each, merge/update `user.js`:
     * If `FirefoxDoH=Disable` -> `mode=5`; **remove** `trr.uri`/`bootstrapAddress` we manage.
     * If `FirefoxDoH=Enable` and `DoHPolicy=Off`   -> `mode=5`.
     * If `FirefoxDoH=Enable` and `DoHPolicy=Allow` -> `mode=2`; **always set `trr.uri` when a known template exists** (and `bootstrapAddress` if appropriate) for determinism; else omit `trr.uri`.
     * If `FirefoxDoH=Enable` and `DoHPolicy=Require` ->
       * If a **known template** exists **and** DoH probe passed (§4.2), set `mode=3` **and** `trr.uri` (plus optional `bootstrapAddress`).
       * If **no known template** or probe fails, **degrade to Allow**: set `mode=2`, optionally keep `trr.uri` if known, and **warn**.
     * If `FirefoxDoH=Enable` and `DoHPolicy=Unchanged` -> `mode=2` as a safe default and, **when known**, set `trr.uri` for determinism; print that this is the safe default.
   * Always print which profiles were updated and the key lines written.
   * If `-PrintDiagnostics`: show additional canary result details (normal info printing will show brief result), any policies detected, and `policies.json` presence (warn if policy overrides user.js).
9. **Summary**:
   * Echo **effective Windows policy** and meaning (read back registry with numeric value),
   * Chrome mode + whether templates are set,
   * Firefox mode per target (if multiple Firefox profiles, show each profile name and say "applied" and then at the end say “Applied to N profiles”),
   * **Registered Windows DoH servers** with **provider labels**,
   * **DNS smoke tests** (e.g., example.com, cloudflare.com, quad9.net).

---

## 8) Error Handling & Idempotency

* **try/catch** around all OS mutations (registry writes, adapter DNS, template registration, file writes).
* Failures in one area **must not** abort other targets.
* Template registration:
  * If the mapping already exists, report **“already registered”** (Before/After equal).
* Firefox `user.js`:
  * Merge by removing existing `network.trr.*` lines we manage, then append our new lines.
  * If a profile cannot be written, print a warning for that profile and continue.
* `netsh` fallback:
  * After using `netsh`, inspect `$LASTEXITCODE`; print success/failure clearly.

---

## 9) PowerShell 5.1 Compliance

* **No** PS7-only syntax: no `?:` ternary, no `??` null-coalesce, no `-isnot` shortcuts, etc.
* Use `if/else` and classic .NET (`New-Object`, `System.Net.Http.HttpClient`).
* **Do not** use `$Host` or `$host` as a variable/param name anywhere (it’s reserved). Prefer `$targetHost`/`$dohHost`.
* When diagnosing `Test-NetConnection`, avoid `-InformationLevel Quiet` if `-PrintDiagnostics` is set; otherwise concise is okay.

---

## 10) Acceptance Criteria (what “done” looks like)

1. **Unified semantics**: Running the same “Require” intent results in:
   * Windows: `DoHPolicy=2` (Require), only if preflight passes; otherwise Allow (1).
   * Chrome: `DnsOverHttpsMode=secure` + templates if known (else `automatic` + warning).
   * Firefox: `trr.mode=3` + `trr.uri`, else `mode=2` + warning.
2. **Always-safe**: With `-PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9`:
   * The script shows 443 checks OK, DoH probes OK (POST or fallback GET),
   * Windows does Allow then Require successfully,
   * Browser settings reflect the intended modes,
   * No name resolution outage occurs after completion.
3. **Independent controls**: Run with and without `-ApplyAdapterDNS` and confirm adapter DNS is only changed when requested.
4. **Diagnostics (additional details printed)**: With `-PrintDiagnostics`, logs include rich details over and above what is normally printed for actions and tests (HTTP statuses, header parse, TLS fallback notes, registry reads, policy readbacks, canary, etc.). Without it, concise pass/fail lines remain.
5. **Idempotent**: Re-running the same command produces “already registered”/“no change” logs, not errors.
6. **PS 5.1**: Script parses and runs on stock Windows 11 PowerShell 5.1 without syntax errors.

---

## 11) Example Runs (illustrative)

* **Windows Require using current adapter DNS** (no adapter change):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File .\configure_DNS_over_HTTPS.ps1 `
  -DoHPolicy Require -WindowsDoH Enable
```

* **Chrome Require (per-user), leave Windows/Firefox unchanged**:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File .\configure_DNS_over_HTTPS.ps1 `
  -DoHPolicy Require `
  -ChromeDoH Enable
```

*(If templates exist from known candidate IPs, this becomes `secure`; else `automatic` with warning.)*

* **Change adapter DNS to Cloudflare + Quad9, do not touch any DoH policy**:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File .\configure_DNS_over_HTTPS.ps1 `
  -ApplyAdapterDNS -PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9
```

* **Everything Require with diagnostics**:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File .\configure_DNS_over_HTTPS.ps1 `
  -DoHPolicy Require `
  -ApplyAdapterDNS -PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9 `
  -WindowsDoH Enable -ChromeDoH Enable -FirefoxDoH Enable `
  -PrintDiagnostics
```

---

## 12) **Potential gaps to review (and address if found)**

* Ensure **Single Policy and Unified semantics** across **all three targets**.
* Ensure ungated **before/after** prints uniformly.
* Add **`-PrintDiagnostics`** commandline switch gate affecting ONLY printing of additional richer diagnostic level information everywhere (eg info relating to Windows, Chrome, Firefox, DoH probe, and all other tests/checks/actions) and without gating any actions/behavior.
* Ensure try/catch for all actions and tests eg all cmdlets and netsh etc
* Ensure checking of all return statuses
* Ensure confirmation-it-worked tests on actions wherever possible 

## Addendum / Clarifications

### A. Audience & Preconditions

* **Who this is for:** Windows admins or power users comfortable running PowerShell **as Administrator** when touching Windows settings.
* **Where it runs:** Windows 11 with **PowerShell 5.1**. (No PS7-only syntax or modules.)
* **Network reality check:** If you’re on a **captive portal**, **enterprise proxy**, or **SSL-inspecting** network, DoH probes can fail even if plain DNS works. The script won’t force Require if probes fail.

### B. Privilege Model (Very Important)

* **Admin elevation is required** for:
  * Writing Windows DoH policy (`HKLM`),
  * Registering DoH templates (cmdlet or `netsh`),
  * Changing adapter DNS servers.
* **User level (non-admin)** is fine for:
  * Chrome HKCU policy (per-user),
  * Firefox `user.js` in the user’s profile(s).
* The script should **only check for admin** when it’s actually going to modify Windows state.

### C. Feature Availability & Fallbacks

* **Windows DoH cmdlets** (`Add-DnsClientDohServerAddress`, etc.) exist on modern Windows 10/11 builds. If a cmdlet isn’t available or throws, the script **falls back to `netsh dns add/show encryption`**.
* **Firefox DoH** works via prefs (`user.js`). No enterprise policy is required; if policy **does** exist, it **overrides** prefs—script warns and proceeds, but tells you prefs may be ignored.
* **Chrome** must be configured via **policy** (HKCU) to be deterministic; `chrome://settings` toggles can be user-modified, but policy wins.

### D. Unified Semantics (One Intent, Three Knobs)

* “**Off**”: plaintext DNS only.
* “**Allow**”: prefer DoH, **fallback allowed** to plaintext.
* “**Require**”: DoH only (no plaintext fallback).

### E. Safety Rails Quick Reference

* **Probes always run** (verbosity only changes what’s printed).
* **Windows Require is staged**: set **Allow -> flush -> OS smoke test -> Require** (promote only if safe).
* **Chrome “secure” only** if templates are known; else **automatic** with a warning.
* **Firefox `mode=3` only** if a template is known and at least one DoH probe succeeded; else `mode=2` with a warning.
* **Adapter DNS** changes only when `-ApplyAdapterDNS` **and** at least one IP was provided.

### F. Canary Test (Firefox) — What a Newcomer Should Know

* **Meaning:** If `use-application-dns.net` resolves via the **OS DNS**, the network is signaling “don’t auto-enable DoH.”
* **Effect:** Impacts automatic/rollout behavior; **doesn’t override** an explicit `network.trr.mode` setting. Enterprise policy overrides prefs regardless of canary.
* **Why test:** Explains Firefox behavior and aids diagnostics.

### G. Verification Checklist (Post-Run)

* **Windows:** registry policy value; `netsh dns show encryption`; `Resolve-DnsName` works.
* **Chrome:** `chrome://policy` shows mode/templates; `chrome://dns` after restart.
* **Firefox:** `about:config` (`network.trr.mode`, `network.trr.uri`); `about:policies`; `about:networking#dns` (TRR column) after browsing.

* **Windows:**
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy` = 0/1/2 as expected.
  * `netsh dns show encryption` shows your IP->template.
  * `Resolve-DnsName example.com` works (if Require was set, resolution should still succeed).

* **Chrome:**
  * `chrome://policy` shows `DnsOverHttpsMode` and (when secure) `DnsOverHttpsTemplates`.
  * `chrome://dns` can show DoH status (requires restart after policy change).

* **Firefox:**
  * `about:config` -> `network.trr.mode` (2 or 3) and `network.trr.uri` set when required.
  * `about:policies` shows **inactive** if no policy is governing DoH (or explains overrides).
  * `about:networking#dns` shows TRR usage when active (TRR column true), after some browsing.
### H. Known DoH Templates & Labels (Practical Advice)

* Maintain small IPv4->template map for common resolvers (Cloudflare, Quad9, Google, OpenDNS, AdGuard, CleanBrowsing, Aussie Broadband).
* If the IP is **unknown**:
  * Windows **Allow** is still fine,
  * Windows **Require** is **blocked**,
  * Chrome **secure** degrades to **automatic**,
  * Firefox **mode=3** degrades to **mode=2**.

### I. Network Quirks to Expect

* **MITM / TLS inspection:** DoH POST/GET may return 200 but with **non-DNS payload**. The script checks **Content-Type** and validates the **DNS header** (QR, RCODE) to avoid false positives.
* **Proxies:** System proxy settings can interfere with direct DoH; if the environment mandates a proxy, the script’s `HttpClient` may need default proxy usage (system default is typically fine).
* **Captive portals:** Expect probes to fail until signed in.

### J. Timeouts & Retries

* DoH probe attempts: **POST first**, then **GET fallback**; **SystemDefault TLS first**, then **TLS 1.2** once; **restore** original TLS setting at the end.
* Keep timeouts short enough not to stall the run (e.g., a couple of seconds), but long enough to avoid flaky failures on latent links.

### K. Idempotency Rules

* Windows template mapping already exists -> **“already registered”**.
* If Adapter DNS already matches requested -> Before/After show no change.
* Re-running the same command yields confirmations and summaries, not errors.

### L. Logging & Supportability

* `-PrintDiagnostics` is **the “turn everything up” diagnostic info printing switch**: dump as much info as possible including from objects from `Test-NetConnection`, parse headers, hex previews, registry reads, detected Firefox policies, profiles touched, Chrome HKCU reads, etc etc etc — but **it must NOT change behaviors**.

* Optional future improvement (not required here): `-LogPath` to tee output to a file.

### M. Common Pitfalls

* Expecting Windows changes without running **as Administrator** when needed.
* Forgetting browser restart to pick up policy/user.js changes.
* Expecting `Require` to stick with **unknown resolver IPs** or when **DoH probes fail**.
* Using **PS7 syntax or cmdlets etc** in a script which MUST be compatible with Powershell 5.1.
* Accidentally using `$Host` as a variable (it’s reserved in PowerShell).

### N. Minimal Test Matrix

1. **Allow everywhere, no adapter change**  
   `-DoHPolicy Allow -WindowsDoH Enable -ChromeDoH Enable -FirefoxDoH Enable`
2. **Require everywhere with known IPs**  
   `-DoHPolicy Require -ApplyAdapterDNS -PrimaryDNS 1.1.1.1 -SecondaryDNS 9.9.9.9 -WindowsDoH Enable -ChromeDoH Enable -FirefoxDoH Enable`
3. **Chrome only (Require semantics)**  
   `-DoHPolicy Require -ChromeDoH Enable` (verify `chrome://policy`; if no templates known, expect `automatic`)
4. **Firefox only (Require semantics)**  
   `-DoHPolicy Require -FirefoxDoH Enable` (verify `trr.mode=3` + `trr.uri`; if no template/probe, expect `mode=2` + warning)

**All tests always run** regardless of verbosity.
