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

## 3. Detailed Findings (Actionable Fixes for Medium & Critical Low Issues)

### 🔧 1. Missing Content Security Policy (CSP)  
**Where to Fix:**  
- **Apache Server:** Edit `.htaccess` file in the website root folder  
  (Location: `/var/www/vendor.iium.edu/public_html/.htaccess`)  
  **Add this line:**  
  ```apache
  Header set Content-Security-Policy "default-src 'self'; script-src 'self'"
  ```
- **Nginx Server:** Edit the site config file (`/etc/nginx/sites-available/vendor.iium.edu.my`)  
  **Add inside `server { }` block:**  
  ```nginx
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'";
  ```

**Tools Needed:**  
- Text editor (VS Code, Nano)  
- Server access (SSH for Apache/Nginx)  

**Validation:**  
After saving, check headers at: https://securityheaders.com/

---

###  2. Anti-Clickjacking (Missing X-Frame-Options)  
**Where to Fix:**  
Same files as CSP above:  
- **Apache (.htaccess):**  
  ```apache
  Header set X-Frame-Options "DENY"
  ```
- **Nginx (config file):**  
  ```nginx
  add_header X-Frame-Options "DENY";
  ```

**Quick Test:**  
Try embedding your page in an iframe – it should now block loading.

---

### 3. Outdated Bootstrap Library  
**Steps to Fix:**  
1. **Download latest Bootstrap** from: https://getbootstrap.com/docs/5.3/getting-started/download/  
2. **Replace old file:**  
   - Current path: `/assets/b635246e/js/bootstrap.js`  
   - Upload new files to same folder  
3. **Update HTML references:**  
   Change:  
   ```html
   <script src="/assets/b635246e/js/bootstrap.js"></script>
   ```
   To:  
   ```html
   <script src="/assets/js/bootstrap.bundle.min.js"></script> 
   ```

**Tools Needed:**  
- FTP/SFTP access (FileZilla, WinSCP)  
- Code editor  

---

### 4. Cookie Security Flags (Secure/SameSite)  
**Where to Fix (PHP Example):**  
Edit the PHP script that sets cookies (likely in login scripts):  
```php
setcookie(
    '_csrf-backend', 
    $token, 
    [
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]
);
```

**Location Examples:**  
- `/adm/site/login.php`  
- `/includes/auth_functions.php`  

**Check After Fix:**  
Use Chrome DevTools → Application → Cookies to verify flags.

---

### 5. Hide Server Version (Apache)  
**Edit Apache Config:**  
1. Open `/etc/httpd/conf/httpd.conf`  
2. Add these lines:  
   ```apache
   ServerTokens Prod
   ServerSignature Off
   ```
3. Restart Apache:  
   ```bash
   sudo systemctl restart httpd
   ```

**For PHP Version:**  
Edit `php.ini` (usually `/etc/php.ini`):  
```ini
expose_php = Off
```

---

### 6. Enable HSTS  
**Add to .htaccess (Apache):**  
```apache
Header set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

**For Nginx:**  
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
```

**Warning:**  
Test HTTPS fully before enabling – mistakes can break access.

---

### Required Software/Tools List  
| Task | Tool | Download Link |
|------|------|---------------|
| Edit server config | VS Code / Nano | https://code.visualstudio.com/ |
| File transfer | WinSCP / FileZilla | https://winscp.net/ |
| Header validation | SecurityHeaders.com | https://securityheaders.com/ |
| Bootstrap update | Official Site | https://getbootstrap.com/ |
| Server restart | SSH Client (PuTTY) | https://www.putty.org/ |

**Notes:**  
- Always **backup files** before editing (e.g., `cp httpd.conf httpd.conf.bak`)  
- Changes may require **server restart** to take effect  
- Test in **staging environment** first if available  

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

  
## fas.iium.edu.my

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

## Recommendation (CSP Header)

### 🛠️ Option A: Using Apache `.htaccess`

1. Navigate to:
   ```
   /var/www/html/fas/public/.htaccess
   ```

2. Add this line at the top:
   ```apache
   Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';"
   ```

3. Restart Apache:
   ```bash
   sudo systemctl restart httpd
   ```

---

### Option B: Using Laravel Middleware

1. Create middleware:
   ```bash
   php artisan make:middleware CSPHeader
   ```

2. Add logic in `app/Http/Middleware/CSPHeader.php`:
   ```php
   <?php

   namespace App\Http\Middleware;

   use Closure;
   use Illuminate\Http\Request;

   class CSPHeader
   {
       public function handle(Request $request, Closure $next)
       {
           $response = $next($request);
           $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';");
           return $response;
       }
   }
   ```

3. Register in `app/Http/Kernel.php`:
   ```php
   protected $middleware = [
       // Other middleware...
       \App\Http\Middleware\CSPHeader::class,
   ];
   ```

---

### 📖 Explanation of CSP Directives

| Directive                          | Description                                                              |
|-----------------------------------|--------------------------------------------------------------------------|
| `default-src 'self'`              | Allows all content from same origin                                      |
| `script-src 'self'`               | Restricts JavaScript to same origin                                      |
| `style-src 'self' 'unsafe-inline'`| Allows inline styles for Laravel blade + same origin styles              |
| `img-src 'self' data:`            | Allows images from same origin + base64 (e.g., icons)                    |
| `font-src 'self'`                 | Restricts font loading to same origin                                    |
| `frame-ancestors 'none'`          | Prevents the site from being embedded (protects against clickjacking)   |

---

### Files to Edit

| File                                         | Purpose                                      |
|---------------------------------------------|----------------------------------------------|
| `public/.htaccess`                          | Apply CSP header via Apache                  |
| `app/Http/Middleware/CSPHeader.php`         | Laravel middleware to inject CSP header      |
| `app/Http/Kernel.php`                       | Register middleware globally                 |

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

## Recommendation (Clickjacking Protection)

### Option A: Using Apache `.htaccess`

1. Navigate to:
   ```
   /var/www/html/fas/public/.htaccess
   ```

2. Add the following lines:
   ```apache
   Header always set X-Frame-Options "DENY"
   Header always set Content-Security-Policy "frame-ancestors 'none';"
   ```

3. Restart Apache:
   ```bash
   sudo systemctl restart httpd
   ```

---

### Option B: Using Laravel Middleware

1. Create middleware:
   ```bash
   php artisan make:middleware ClickjackingProtection
   ```

2. Add logic in `app/Http/Middleware/ClickjackingProtection.php`:
   ```php
   <?php

   namespace App\Http\Middleware;

   use Closure;
   use Illuminate\Http\Request;

   class ClickjackingProtection
   {
       public function handle(Request $request, Closure $next)
       {
           $response = $next($request);
           $response->headers->set('X-Frame-Options', 'DENY');
           $response->headers->set('Content-Security-Policy', "frame-ancestors 'none';");
           return $response;
       }
   }
   ```

3. Register in `app/Http/Kernel.php`:
   ```php
   protected $middleware = [
       // Other middleware...
       \App\Http\Middleware\ClickjackingProtection::class,
   ];
   ```

---

### Files to Edit

| File                                               | Purpose                                        |
|----------------------------------------------------|------------------------------------------------|
| `public/.htaccess`                                | Apache header implementation                   |
| `app/Http/Middleware/ClickjackingProtection.php`  | Laravel middleware for anti-clickjacking       |
| `app/Http/Kernel.php`                             | Middleware registration                        |


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

# 🔐 Web Application Vulnerability Scan Report

**Target Application:** https://bpn.iium.edu.my  
**Tool Used:** OWASP ZAP 2.16.1  
**Date of Scan:** 2025-06-16  
**Scanned By:** Auni Haziqah Binti Azizi  
**Scan Type:** Passive Scan  
**Scan Duration:** 10:15 AM – 10:44 AM  

---

## 📋 1. Executive Summary

| Metric                  | Value |
|------------------------|-------|
| Total Issues Identified| 16    |
| Critical Issues        | 0     |
| High-Risk Issues       | 0     |
| Medium-Risk Issues     | 5     |
| Low-Risk Issues        | 7     |
| Informational Issues   | 4     |
| Remediation Status     | Pending |

> 🟡 **Key Takeaway:**  
The BPN IIUM portal has **5 medium-risk vulnerabilities**, mainly due to **missing security headers** and **outdated libraries**. These should be addressed promptly to prevent Cross-Site Scripting (XSS), clickjacking, CSRF, or potential data leakage.

---

## 📊 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability         |
|------------|------------------|-------------------------------|
| Medium     | 5                | Missing CSP, Sensitive File Leak |
| Low        | 7                | Cookie Flags, Server Info Leak |
| Info       | 4                | Debug Comments, UA Detection  |

---

## 🧯 3. Detailed Findings

### 3.1 🔧 Missing Content Security Policy (CSP)
- **Severity:** Medium  
- **Description:** No `Content-Security-Policy (CSP)` header was set. This weakens protection against XSS and content injection.  
- **Affected URL:** https://bpn.iium.edu.my  

**💼 Business Impact:**  
Attackers could inject malicious scripts that steal user data or alter website content.

**🛠️ Recommendation:**  
Set CSP header to allow only trusted sources:

**Option A – Apache:**
```apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';"

**Option B – Laravel Middleware:**
Create middleware CSPHeader and inject the CSP header as shown in the FAS report.

3.2 📁 Exposed Sensitive File
Severity: Medium

Description: A sensitive file (e.g., .env, .git, backup zip) was found accessible to the public.

💼 Business Impact:
Could leak database credentials, API keys, or internal logic.

## 4.🛠️ Recommendation:

Immediately remove the file or restrict access using:

IP whitelisting

Authentication

.htaccess or Nginx config

## 3.3 ❌ Missing Anti-Clickjacking Protection
Severity: Medium

Description: The application lacks the X-Frame-Options or Content-Security-Policy: frame-ancestors headers.
💼 Business Impact:
Hackers can embed the site in a hidden iframe to trick users into clicking malicious elements (clickjacking).

🛠️ Recommendation:
Option A – Apache:

apache
Copy
Edit
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'none';"
Option B – Laravel Middleware:
Create a ClickjackingProtection middleware as shown in the FAS report.

## 3.4 📦 Vulnerable JavaScript Library
Severity: Medium
Description: An outdated third-party JS library is in use.

💼 Business Impact:
Legacy JS libraries may contain known vulnerabilities that attackers can exploit (e.g., DOM-based XSS).

🛠️ Recommendation:
-Identify the outdated JS version (e.g., jQuery, Bootstrap).
-Upgrade to the latest secure version.
-Use npm audit or OWASP Dependency-Check for future alerts.

## 3.5 🚨 Cookie Issues (Secure & SameSite Missing)
Severity: Low
Description: Some cookies do not include Secure or SameSite attributes.

💼 Business Impact:
Cookies without these flags may be transmitted over HTTP or shared across domains — increasing CSRF/session hijack risk.

🛠️ Recommendation:
Update cookies like this:
-http
-Copy
-Edit
-Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict

## 🧱 4. Additional Issues

| Vulnerability                       | Severity | Fix Summary                                                  |
|------------------------------------|----------|--------------------------------------------------------------|
| Server Version Leak (Server header)| Low      | Mask/suppress version info (e.g., `ServerTokens Prod`)       |
| X-Powered-By Header Disclosure     | Low      | Remove `X-Powered-By` header via PHP or server config        |
| Missing HSTS Header                | Low      | Add `Strict-Transport-Security: max-age=31536000;`           |
| MIME Sniffing Allowed              | Low      | Add `X-Content-Type-Options: nosniff`                        |
| Cross-Domain JS Inclusion          | Low      | Restrict `<script src="">` to trusted domains                |
| Big Redirect with Body             | Low      | Avoid exposing data in redirects                             |
| Suspicious JS/HTML Comments        | Info     | Remove debug/internal comments before production             |
| Session Token in Response Header   | Info     | Ensure tokens are not exposed; use `Secure`/`HttpOnly` flags |
| User-Agent Behavior Variation      | Info     | Normalize or monitor for suspicious UA changes               |
| Cache-Control Misconfigured        | Info     | Use `Cache-Control: no-store, no-cache, must-revalidate`     |

---

## ✅ 5. Next Steps & Action Plan

| Task                                 | Owner               | Deadline     |
|--------------------------------------|----------------------|--------------|
| Implement CSP & Anti-Clickjacking    | DevOps Team          | 2025-07-20   |
| Remove exposed sensitive files       | Backend/Infra Team   | 2025-07-20   |
| Upgrade vulnerable JS libraries      | Frontend Team        | 2025-07-22   |
| Fix cookie flags                     | Backend Team         | 2025-07-30   |
| Re-scan website to validate fixes    | Security Team        | 2025-08-05   |


## 🔐 6. Prevention Strategy
Short-Term:
-Add missing headers via Laravel or server config
-Restrict access to sensitive files
-Review and upgrade third-party JS libraries

Long-Term:
=Perform vulnerability scans quarterly
-Follow OWASP Secure Coding Practices
-Add security checks in CI/CD pipelines
-Conduct annual penetration tests

📎 Appendix
Scan Scope: https://bpn.iium.edu.my
Scan Type: Passive Scan (No authentication)
Tool: OWASP ZAP v2.16.1

✍️ Prepared By
Auni Haziqah Binti Azizi
Matric Number: 2116050
📅 Date: 2025-07-10


