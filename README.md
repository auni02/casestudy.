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

## 1. Executive Summary

| **Metric**                  | **Value** |
|----------------------------|-----------|
| Total Issues Identified    | 17        |
| Critical Issues            | 0         |
| High-Risk Issues           | 0         |
| Medium-Risk Issues         | 3         |
| Low-Risk Issues            | 7         |
| Informational Issues       | 7         |
| Remediation Status         | Pending   |

### 🔑 Key Takeaway

The security assessment identified **3 medium-risk vulnerabilities**, including:

- Missing **Content Security Policy (CSP)**
- Outdated **Bootstrap library** (CVE-2024-6484)

These require **prioritized remediation**.

While **no critical or high-risk issues** were found, the report includes:

- **7 low-risk misconfigurations**  
  *(e.g., insecure cookies, missing security headers)*
- **7 informational findings**  
  *(e.g., authentication flow details)*

Addressing these findings will help strengthen the overall **security posture** of the application.

## 2. Summary of Findings

| **Risk Level** | **Number of Issues** | **Example Vulnerability** |
|----------------|----------------------|----------------------------|
| Critical       | 0                    | N/A (No critical issues found) |
| High           | 0                    | N/A (No high-risk issues found) |
| Medium         | 3                    | 1. Missing Content Security Policy (CSP) Header  
|                |                      | 2. Vulnerable JS Library (Bootstrap 3.4.1 - CVE-2024-6484)  
|                |                      | 3. Missing Anti-Clickjacking Header (X-Frame-Options) |
| Low            | 7                    | 1. Server Leaks Version Info (Apache/PHP)  
|                |                      | 2. Missing HSTS Header  
|                |                      | 3. Cookies Without Secure/SameSite Attributes  
|                |                      | 4. Missing X-Content-Type-Options Header |
| Informational  | 7                    | 1. Authentication Request Identified  
|                |                      | 2. Big Redirect with Potential Info Leak  
|                |                      | 3. Server Banner Exposure |

### 🧐 Key Observations

- **Top Risks:**
  - **Medium:** Missing security headers (e.g., CSP, X-Frame-Options) and usage of an outdated library (Bootstrap 3.4.1).
  - **Low:** Predominantly cookie misconfigurations and server information leaks.

- **No Critical or High-Risk Issues:**
  - No immediate exploitation vectors such as **Remote Code Execution (RCE)** or **SQL Injection (SQLi)** were identified.

## 3. Detailed Findings

---

### 1. Missing Content Security Policy (CSP) Header  
**Severity:** Medium  

**Description:**  
The application does not implement a Content Security Policy, leaving it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.

**Affected URLs:**
- https://vendor.iium.edu.my/sitemap.xml  
- https://vendor.iium.edu.my/

**Business Impact:**  
Attackers could inject malicious scripts to steal user data or deface the website.

**OWASP Reference:**  
[OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

**Recommendation:**  
Add a CSP header like:  
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

**Prevention Strategy:**
- Implement CSP in server configurations.
- Regularly audit headers using security tools.

**Responsible Team:** DevOps  
**Target Remediation Date:** 2025-07-31

---

### 2. Vulnerable JavaScript Library (Bootstrap 3.4.1)  
**Severity:** Medium  

**Description:**  
An outdated Bootstrap version (3.4.1) with known vulnerabilities (CVE-2024-6484) is in use.

**Affected URL:**
- https://vendor.iium.edu.my/assets/b635246e/js/bootstrap.js

**Business Impact:**  
Exploitable vulnerabilities could compromise user sessions or lead to DOM-based attacks.

**OWASP Reference:**  
[OWASP A06:2021 - Vulnerable Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

**Recommendation:**  
Upgrade to **Bootstrap 5.x** or later.

**Prevention Strategy:**
- Establish a patch management process.
- Use dependency scanners (e.g., OWASP Dependency Check).

**Responsible Team:** Frontend Development  
**Target Remediation Date:** 2025-07-15

---

### 3. Missing Anti-Clickjacking Header  
**Severity:** Medium  

**Description:**  
Missing `X-Frame-Options` or `CSP frame-ancestors` directive exposes the site to clickjacking.

**Affected URL:**
- https://vendor.iium.edu.my/

**Business Impact:**  
Attackers could embed the site in iframes to trick users into unintended actions.

**OWASP Reference:**  
[OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

**Recommendation:**  
Add the following header:  X-Frame-Options: DENY 


**Prevention Strategy:**
- Include headers in all responses.
- Test with tools like ZAP or Burp Suite.

**Responsible Team:** DevOps  
**Target Remediation Date:** 2025-07-31

---

### 4. Server Version Information Leak  
**Severity:** Low  

**Description:**  
Server headers expose `Apache/2.4.6 (CentOS)` and `PHP/7.4.27`, revealing outdated software versions.

**Affected URLs:**  
All endpoints (e.g., `/robots.txt`, `/adm/site/login`)

**Business Impact:**  
Attackers can target known vulnerabilities in these versions.

**OWASP Reference:**  
[OWASP A01:2021 - Information Exposure](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

**Recommendation:**  
Suppress headers in Apache config:
ServerTokens Prod
ServerSignature Off


**Prevention Strategy:**
- Regular server hardening audits.

**Responsible Team:** Infrastructure  
**Target Remediation Date:** 2025-08-15

---

### 5. Missing Secure/SameSite Cookie Attributes  
**Severity:** Low  

**Description:**  
Cookies like `_csrf-backend` lack `Secure` and `SameSite` attributes.

**Affected URLs:**  
Login/session-related endpoints.

**Business Impact:**  
Increased risk of CSRF attacks or cookie theft over HTTP.

**OWASP Reference:**  
[OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

**Recommendation:**  
Update cookies:
Set-Cookie: _csrf-backend=...; Secure; HttpOnly; SameSite=Strict


**Prevention Strategy:**
- Conduct code reviews for cookie settings.

**Responsible Team:** Backend Development  
**Target Remediation Date:** 2025-08-01

## 4. Recommendations & Next Steps

### Immediate Actions
1. **Remediation Priorities**:
   - [ ] Address all **Medium** risks within 30 days (focus order):
     1. Upgrade Bootstrap library (CVE-2024-6484)
     2. Implement CSP and `X-Frame-Options` headers
     3. Fix cookie security attributes (`Secure`, `SameSite`)

### Ongoing Improvements
2. **Security Integration**:
   - [ ] Adopt secure coding standards (OWASP ASVS)
   - [ ] Implement automated security headers (via web server/config)
   - [ ] Establish dependency update process (e.g., Dependabot)

3. **Testing & Compliance**:
   - [ ] Re-scan after fixes (ZAP baseline scan)
   - [ ] Schedule **quarterly** full scans + **monthly** header/dependency checks
   - [ ] Conduct annual penetration testing (external validation)

### Team Responsibilities
| Action Item               | Owner          | Timeline        |
|---------------------------|----------------|-----------------|
| Bootstrap upgrade         | Frontend Team  | 2025-07-15      |
| Header implementation     | DevOps         | 2025-07-31      |
| Cookie fixes              | Backend Team   | 2025-08-01      |
| First re-test             | Security Team  | 2025-08-15      |

## Appendix: Technical Details

### A. Scan Configuration
| Parameter          | Value                          |
|--------------------|--------------------------------|
| Tool Version       | ZAP 2.16.1                     |
| Scan Type          | Automated Passive Scan         |
| Scope              | `https://vendor.iium.edu.my`   |
| Included Contexts  | All (no contexts excluded)     |
| Excluded URLs      | None                           |
| Risk Threshold     | Medium+ (Low/Info logged)      |

### B. Scanned URLs
1. `https://vendor.iium.edu.my/`
2. `https://vendor.iium.edu.my/sitemap.xml`  
3. `https://vendor.iium.edu.my/adm/site/login`  
4. `https://vendor.iium.edu.my/assets/*`  
*(Full list available in `scan_urls.txt`)*

### C. Complete Findings List

| ID     | Risk Level | Vulnerability Type                          | Instances | Affected Components               | Status  |
|--------|------------|---------------------------------------------|-----------|-----------------------------------|---------|
| VLN-01 | Medium     | Missing Content Security Policy (CSP) Header | 2        | All pages                         | Open    |
| VLN-02 | Medium     | Vulnerable JS Library (Bootstrap 3.4.1)      | 1        | `/assets/b635246e/js/bootstrap.js`| Open    |
| VLN-03 | Medium     | Missing X-Frame-Options Header               | 1        | Homepage                          | Open    |
| VLN-04 | Low        | Server Version Disclosure (Apache/2.4.6)     | 21       | All responses                     | Open    |
| VLN-05 | Low        | Missing Strict-Transport-Security Header     | 1        | HTTPS endpoints                   | Open    |
| VLN-06 | Low        | Cookie Without Secure Flag                   | 3        | `_csrf-backend` cookie            | Open    |
| VLN-07 | Low        | Cookie Without SameSite Attribute            | 1        | `advanced-frontend` cookie        | Open    |
| VLN-08 | Low        | X-Content-Type-Options Header Missing        | 34       | All pages                         | Open    |
| VLN-09 | Low        | Information Disclosure in Comments           | 5        | HTML source                       | Open    |
| VLN-10 | Low        | Big Redirect with Sensitive Data             | 1        | `/adm/cas/auth/login`             | Open    |
| VLN-11 | Info       | Modern Web Application Detection             | 5        | Frontend frameworks               | Reviewed|
| VLN-12 | Info       | Authentication Request Identified            | 2        | `/site/login`                     | Reviewed|
| VLN-13 | Info       | Session Management Response Detected         | 5        | Login/logout flows                | Reviewed|
| VLN-14 | Info       | Cache-Control Directives Need Review         | 15       | Static assets                     | Reviewed|
| VLN-15 | Info       | User Agent Fuzzer Detection                  | 12       | Application headers               | Reviewed|
| VLN-16 | Info       | HTML Element Attribute Control               | 6        | Form inputs                       | Reviewed|
| VLN-17 | Info       | Suspicious Comments in Code                  | 5        | JavaScript files                  | Reviewed|

**Legend:**
- 🔴 Open (needs remediation)
- 🟡 Reviewed (requires monitoring)
- 🟢 Closed (remediated)

### D. Additional Resources
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [CVE-2024-6484 Details](https://nvd.nist.gov/vuln/detail/CVE-2024-6484)
- [Security Headers Guide](https://securityheaders.com/)

  
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
