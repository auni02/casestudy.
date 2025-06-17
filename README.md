# casestudy.
# Group:TAMAGO

## Group Members

| Name        | Matric No           | Task              |
|:------------|:--------------:|-------------------:|
| Auni haziqah      | 2116050      |  http://bpn.iium.edu.my   |
| Syazwani binti Rozali      | 2217642      |  http://vendor.iium.edu.my    |
| Nur Atiqah Binti Mat Jusoh      | 2217008      |  https://fas.iium.edu.my   |

## 🔐 vendor.iium.edu.my

| No | Vulnerability | Risk | CWE | Issue Summary | Recommended Fix |
|----|---------------|------|-----|---------------|-----------------|
| 1 | Missing Content Security Policy (CSP) | Medium | 693 | No CSP header allows XSS & injection. | Add `Content-Security-Policy: default-src 'self'`. |
| 2 | Missing Anti‑Clickjacking Header | Medium | 1021 | Page embeddable in iframes → click‑jacking. | Add `X-Frame-Options: DENY` **or** `frame-ancestors 'none'`. |
| 3 | Vulnerable JS Library | Medium | 1104 | Outdated **Bootstrap.js** detected. | Upgrade / replace with latest secure version. |
| 4 | Server Version Leak | Low | 200 | `Server` header discloses software & version. | Hide or set generic `Server` header (e.g., “Apache”). |
| 5 | HSTS Not Enabled | Low | 319 | Users can be downgraded to HTTP. | Add `Strict-Transport-Security` (HSTS). |
| 6 | Big Redirect Info Leak | Low | 201 | Redirect may expose tokens or data in URL/body. | Strip sensitive data; prefer POST. |
| 7 | Cookie Missing **Secure** Flag | Low | 614 | Session cookies can travel over HTTP. | Set `Secure` flag on all sensitive cookies. |
| 8 | Cookie Missing **SameSite** | Low | 1275 | Cookies sent in cross‑site requests → CSRF risk. | Add `SameSite=Lax` or `SameSite=Strict`. |
| 9 | **X‑Powered‑By** Header Leak | Low | 200 | Identifies backend tech stack. | Remove `X-Powered-By` header. |
|10 | Missing **X‑Content‑Type‑Options** | Low | 693 | Allows MIME‑sniffing. | Add `X-Content-Type-Options: nosniff`. |
|11 | Authentication Endpoint Detected | Info | 16 | Login page exposed; brute‑force possible. | Enforce rate‑limiting + MFA. |
|12 | Modern Web Framework Detected | Info | 1104 | Framework fingerprinted. | Monitor & patch dependencies. |
|13 | Session Management Found | Info | 613 | Session cookies observed. | Ensure `HttpOnly`, secure attributes & rotation. |
|14 | HTTP Accessible | Info | 319 | Site reachable on plain HTTP. | Force 301 redirect to HTTPS. |
|15 | Suspicious JS Comments | Info | 200 | Debug comments in prod code. | Remove / obfuscate comments. |
|16 | Cache‑Control Misconfigured | Info | 525 | Sensitive responses might be cached. | Use `Cache-Control: no-store, no-cache, must-revalidate`. |
|17 | User‑Controllable Attribute | Info | 79 | Potential reflected/stored XSS vector. | Strict input validation & output encoding. |

## 🔐 fas.iium.edu.my

| No | Vulnerability | Risk | CWE | Issue Summary | Recommended Fix |
|----|---------------|------|-----|---------------|-----------------|
| 1 | Missing CSP Header | Medium | 693 | No CSP → open to XSS. | Add CSP allowing only trusted origins. |
| 2 | Missing Anti‑Clickjacking Header | Medium | 1021 | Site can be framed → click‑jacking. | Add `X-Frame-Options: DENY` or `frame-ancestors 'none'`. |
| 3 | Cookie Without Secure Flag | Low | 614 | Cookies may travel over HTTP. | Add `Secure` flag. |
| 4 | Cookie Without SameSite | Low | 1275 | CSRF possible. | Add `SameSite=Lax` or `Strict`. |
| 5 | Server Leaks Version Info | Low | 497 | `Server` header reveals version. | Remove / mask version string. |
| 6 | HSTS Header Not Set | Low | 319 | SSL‑stripping risk. | Add HSTS header. |
| 7 | Missing X‑Content‑Type‑Options | Low | 693 | MIME‑sniffing allowed. | Add `X-Content-Type-Options: nosniff`. |

## 🔐 bpn.iium.edu.my

| No | Vulnerability | Risk | CWE | Issue Summary | Recommended Fix |
|----|---------------|------|-----|---------------|-----------------|
| 1 | Missing CSP Header | Medium | 693 | No CSP → XSS/injection risk. | Set `Content-Security-Policy`. |
| 2 | Hidden Sensitive File | Medium | 538 | Exposed file leaks credentials/config. | Remove or protect file (authN/Z, IP allow‑list). |
| 3 | Missing Anti‑Clickjacking Header | Medium | 1021 | No protection against framing. | Add `X-Frame-Options` or `frame-ancestors`. |
| 4 | Vulnerable JS Library | Medium | 1395 | Outdated third‑party JS. | Upgrade to latest library. |
| 5 | Big Redirect With Body | Low | 201 | Redirect may leak sensitive data. | Remove body or sensitive info. |
| 6 | Cookie Missing Secure Flag | Low | 614 | Session cookies over HTTP. | Add `Secure` flag. |
| 7 | Cookie Missing SameSite | Low | 1275 | CSRF risk. | Add `SameSite=Lax/Strict`. |
| 8 | Cross‑Domain JS Inclusion | Low | 829 | Third‑party scripts loaded. | Restrict to trusted domains. |
| 9 | X‑Powered‑By Header Leak | Low | 497 | Tech stack disclosed. | Remove header. |
|10 | Server Version Leak | Low | 497 | `Server` header reveals version. | Suppress or generic server header. |
|11 | HSTS Not Enabled | Low | 319 | HTTP downgrade possible. | Add HSTS header. |
|12 | Missing X‑Content‑Type‑Options | Low | 693 | MIME‑sniffing allowed. | Add `nosniff` header. |
|13 | Suspicious Code Comments | Info | 615 | Comments may reveal internals. | Strip production comments. |
|14 | Misconfigured Cache‑Control | Info | 525 | Sensitive pages cached. | Use `no-store, no-cache`. |
|15 | Session Token in Headers | Info | – | Session identifiers returned. | Confirm secure session management. |
|16 | User‑Agent Fuzzing Response Diff | Info | – | Responses vary by UA; potential exposure. | Standardize UA handling; monitor. |
