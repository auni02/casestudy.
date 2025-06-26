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

# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-06-16  
**Scanned By:** Nur Atiqah Binti Mat Jusoh  
**Target Application:** https://fas.iium.edu.my  
**Scan Type:** Passive  
**Scan Duration:** 09:30 AM – 09:59 AM

---

## 1. Executive Summary

| Metric                         | Value            |
|-------------------------------|------------------|
| Total Issues Identified       | 10               |
| Critical Issues               | 0                |
| High-Risk Issues              | 0                |
| Medium-Risk Issues            | 2                |
| Low-Risk Issues               | 5                |
| Informational Issues          | 3                |
| Remediation Status            | Pending          |

**Key Takeaway:**  
The scan of **https://fas.iium.edu.my** identified **2 medium-risk vulnerabilities** and **5 low-risk vulnerabilities** that require remediation. No critical or high-risk issues were discovered. Applying recommended security headers and cookie protections is necessary to strengthen web application security.

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                  |
|------------|------------------|----------------------------------------|
| Critical   | 0                | -                                      |
| High       | 0                | -                                      |
| Medium     | 2                | Missing Anti-clickjacking Header      |
| Low        | 5                | Cookie Without Secure Flag            |
| Info       | 3                | Session Management Response Identified |

---

## 3. Detailed Findings

### 3.1 Content Security Policy (CSP) Header Not Set

- **Severity:** Medium
- **Description:**  
  Content Security Policy (CSP) is missing. CSP helps protect against Cross-Site Scripting (XSS) and data injection attacks by specifying trusted content sources.

- **Affected URLs:**  
  - https://fas.iium.edu.my  
  - https://fas.iium.edu.my/robots.txt  
  - https://fas.iium.edu.my/sitemap.xml  

- **Business Impact:**  
  Without CSP, malicious actors could exploit XSS vulnerabilities, potentially leading to data breaches or hijacking of user sessions.

- **OWASP Reference:**  
  [OWASP A03 - Injection](https://owasp.org/www-project-top-ten/A03_2021-Injection/)

- **Recommendation:**  
  Add a `Content-Security-Policy` HTTP header specifying allowed sources for scripts, styles, and other resources.

- **Prevention Strategy:**  
  - Enforce strong CSP directives.
  - Regularly test web pages for script injection.
  - Conduct routine security audits.

> **Responsible Team:** IIUM IT Web Development Team  
> **Target Remediation Date:** 2025-07-15

---

### 3.2 Missing Anti-clickjacking Header

- **Severity:** Medium
- **Description:**  
  Missing anti-clickjacking protection allows attackers to embed the site within an iframe, tricking users into performing unintended actions.

- **Affected URL:**  
  - https://fas.iium.edu.my  

- **Business Impact:**  
  Potential exploitation via clickjacking attacks, leading to unauthorized transactions or disclosure of sensitive user actions.

- **OWASP Reference:**  
  [OWASP A01 - Broken Access Control](https://owasp.org/www-project-top-ten/A01_2021-Broken_Access_Control/)

- **Recommendation:**  
  Implement either:  
  - `X-Frame-Options: DENY`  
  - or `Content-Security-Policy: frame-ancestors 'none'`

- **Prevention Strategy:**  
  - Apply HTTP headers through web server configuration.
  - Review page access controls regularly.

> **Responsible Team:** IIUM IT Infrastructure Team  
> **Target Remediation Date:** 2025-07-15

---

### 3.3 Low-Risk Vulnerabilities

| Vulnerability                                | Instances | Recommendation Summary                                          |
|----------------------------------------------|-----------|-----------------------------------------------------------------|
| **Cookie Without Secure Flag**               | 3         | Set `Secure` attribute on cookies to enforce HTTPS-only usage.  |
| **Cookie Without SameSite Attribute**        | 3         | Add `SameSite=Strict` or `SameSite=Lax` to all cookies.         |
| **Server Leaks Version Information**         | 3         | Configure server to hide version information from responses.    |
| **Strict-Transport-Security Header Missing** | 3         | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. |
| **X-Content-Type-Options Header Missing**    | 1         | Include `X-Content-Type-Options: nosniff` in server responses.  |

> **Responsible Team for All Low-Risk Issues:** IIUM Web Security Team  
> **Target Remediation Date:** 2025-07-30

---

### 3.4 Informational Findings

| Vulnerability                       | Instances | Note                                         |
|-------------------------------------|-----------|----------------------------------------------|
| **Modern Web Application**          | 1         | Informational only, indicates dynamic content. |
| **Re-examine Cache-Control Directives** | 1       | Review cache settings for sensitive data.   |
| **Session Management Response Identified** | 3     | Detected session identifiers; informational only. |

---

## 4. Recommendations & Next Steps

1. **Remediate Medium-risk vulnerabilities** as a priority.
2. **Implement missing security headers** (CSP, X-Frame-Options, HSTS, etc.).
3. **Enforce secure cookie attributes** (`Secure`, `SameSite`) to prevent CSRF and session hijacking.
4. **Conduct post-remediation testing** to confirm fixes.
5. **Adopt secure coding guidelines** for future development.
6. **Schedule vulnerability scans** every quarter or before major releases.
7. **Consider engaging penetration testers** for deeper assessment.

---

## Appendix

**Scan Configuration:**  
- Tool: OWASP ZAP 2.16.1  
- Mode: Passive Scan  
- Scope: Entire domain of https://fas.iium.edu.my

**Scanned URLs:**  
- https://fas.iium.edu.my  
- https://fas.iium.edu.my/robots.txt  
- https://fas.iium.edu.my/sitemap.xml

---

**Prepared by:**  
NUR ATIQAH BINTI MAT JUSOH, 2217008
Email: nratiqahmj@gmail.com 
Date: 2025-06-15


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

## 1. Executive Summary

| Metric                         | Value  |
|-------------------------------|--------|
| Total Issues Identified       | 16     |
| Critical Issues               | 0      |
| High-Risk Issues              | 0      |
| Medium-Risk Issues            | 5      |
| Low-Risk/Informational Issues | 11     |
| Remediation Status            | Pending |

**Key Takeaway:**  
The BPN portal is missing several essential security headers and cookie protections. While no critical vulnerabilities were found, the identified weaknesses—especially missing CSP, anti-clickjacking headers, and insecure cookies—may lead to Cross-Site Scripting (XSS), CSRF, and session hijacking risks.

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability         |
|------------|------------------|-------------------------------|
| Critical   | 0                | –                             |
| High       | 0                | –                             |
| Medium     | 5                | Missing CSP, Clickjacking     |
| Low        | 9                | Insecure Cookies, JS Inclusion|
| Info       | 2                | Server Info Leak, Comments    |

---

## 3. Detailed Findings

### 1. Missing Content Security Policy (CSP)

- **Severity:** Medium  
- **Description:** CSP header not set. This leaves the site vulnerable to XSS and data injection attacks.  
- **Affected URL:** https://bpn.iium.edu.my  
- **Business Impact:** May allow malicious scripts to execute in users’ browsers.  
- **CWE Reference:** [CWE-693](https://cwe.mitre.org/data/definitions/693.html)  
- **Recommendation:** Set `Content-Security-Policy: default-src 'self';`  
- **Prevention Strategy:** Define CSP in all HTTP responses.

---

### 2. Hidden Sensitive File Found

- **Severity:** Medium  
- **Description:** A sensitive file was discovered as publicly accessible.  
- **Business Impact:** May expose configuration, credentials, or internal logic.  
- **CWE Reference:** [CWE-538](https://cwe.mitre.org/data/definitions/538.html)  
- **Recommendation:** Disable unnecessary files or restrict access via authentication or IP filtering.  

---

### 3. Missing Anti-Clickjacking Header

- **Severity:** Medium  
- **Description:** No `X-Frame-Options` or CSP `frame-ancestors` directive detected.  
- **Business Impact:** The page can be embedded in an iframe and used for clickjacking.  
- **CWE Reference:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)  
- **Recommendation:** Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.

---

### 4. Vulnerable JavaScript Library

- **Severity:** Medium  
- **Description:** Detected use of an outdated JavaScript library.  
- **Business Impact:** May expose client-side attack vectors.  
- **CWE Reference:** [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)  
- **Recommendation:** Update or remove the affected JavaScript library.

---

### 5. Big Redirect Detected

- **Severity:** Low  
- **Description:** Redirect contains content or tokens that may leak sensitive data.  
- **CWE Reference:** [CWE-201](https://cwe.mitre.org/data/definitions/201.html)  
- **Recommendation:** Ensure redirect responses do not include sensitive data or long body content.

---

### 6. Cookies Missing Secure Flag

- **Severity:** Low  
- **Description:** Session cookies set without the `Secure` flag.  
- **Business Impact:** Risk of interception over unencrypted channels.  
- **CWE Reference:** [CWE-614](https://cwe.mitre.org/data/definitions/614.html)  
- **Recommendation:** Add `Secure` flag to all sensitive cookies.

---

### 7. Cookies Missing SameSite Attribute

- **Severity:** Low  
- **Description:** Cookies lack `SameSite` attribute, exposing them to CSRF attacks.  
- **CWE Reference:** [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html)  
- **Recommendation:** Add `SameSite=Lax` or `SameSite=Strict` to cookies.

---

### 8. Cross-Domain JavaScript Inclusion

- **Severity:** Low  
- **Description:** JavaScript is included from external sources.  
- **CWE Reference:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html)  
- **Recommendation:** Allow only scripts from trusted and verified domains.

---

### 9. X-Powered-By Header Disclosure

- **Severity:** Low  
- **Description:** Server response includes `X-Powered-By` header, revealing tech stack.  
- **CWE Reference:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  
- **Recommendation:** Remove or mask `X-Powered-By` in HTTP headers.

---

### 10. Server Version Disclosure via HTTP Header

- **Severity:** Low  
- **Description:** The `Server` header reveals software version.  
- **CWE Reference:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  
- **Recommendation:** Configure server to suppress or genericize this header.

---

### 11. Strict-Transport-Security Header Not Set

- **Severity:** Low  
- **Description:** HSTS policy not enforced, increasing downgrade attack risks.  
- **CWE Reference:** [CWE-319](https://cwe.mitre.org/data/definitions/319.html)  
- **Recommendation:** Add `Strict-Transport-Security` header to enforce HTTPS.

---

### 12. Missing X-Content-Type-Options Header

- **Severity:** Low  
- **Description:** Absence of this header may allow MIME-type sniffing.  
- **CWE Reference:** [CWE-693](https://cwe.mitre.org/data/definitions/693.html)  
- **Recommendation:** Set `X-Content-Type-Options: nosniff`.

---

### 13. Suspicious HTML/JS Comments

- **Severity:** Info  
- **Description:** Page contains debug or internal comments.  
- **CWE Reference:** [CWE-615](https://cwe.mitre.org/data/definitions/615.html)  
- **Recommendation:** Remove or obfuscate sensitive comments before deployment.

---

### 14. Misconfigured Cache-Control Headers

- **Severity:** Info  
- **Description:** Insecure resources may be cached by browsers/proxies.  
- **CWE Reference:** [CWE-525](https://cwe.mitre.org/data/definitions/525.html)  
- **Recommendation:** Use `Cache-Control: no-store, no-cache, must-revalidate`.

---

### 15. Session Token in HTTP Response Headers

- **Severity:** Info  
- **Description:** Detected session ID in headers.  
- **CWE Reference:** [CWE-613](https://cwe.mitre.org/data/definitions/613.html)  
- **Recommendation:** Ensure tokens are protected and use `HttpOnly`, `Secure`.

---

### 16. User-Agent Fuzzing Behavior

- **Severity:** Info  
- **Description:** Site behavior changes based on User-Agent input.  
- **Recommendation:** Normalize responses and avoid leaking special logic via UA detection.

---

## 4. Recommendations & Next Steps

- Immediately configure missing HTTP headers (CSP, HSTS, Anti-Clickjacking).
- Fix cookie attributes and session handling.
- Remove sensitive or unnecessary debug information from production.
- Review and update third-party JavaScript libraries.
- Conduct regular vulnerability assessments.


