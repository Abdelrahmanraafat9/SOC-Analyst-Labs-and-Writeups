# 🔍 Incident Response Report: RetailBreach PCAP Investigation

- **Platform:** CyberDefenders
- **Category:** Network Forensics / Web Application Forensics
- **Difficulty:** Medium
- **Tools Used:** Wireshark
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An investigation was initiated for the **ShopSphere** online retail platform following suspicious administrative logins outside business hours and customer account anomalies. 

Full packet capture (`RetailBreach.pcap`) triage using Wireshark revealed an attacker leveraging directory brute-forcing to discover hidden directories, injecting a malicious **Stored Cross-Site Scripting (XSS)** payload into the `/reviews.php` endpoint. When the site administrator (`135.143.142.5`) browsed the page, the XSS script executed, stealing the administrator's `PHPSESSID` session token. The attacker (`111.224.180.128`) subsequently hijacked the administrative session to perform a **Path Traversal** attack against `/log_viewer.php` to exfiltrate sensitive OS files (`/etc/passwd`).

--
<img width="1341" height="651" alt="Screenshot 2026-09-21 172457" src="https://github.com/user-attachments/assets/364982ca-df73-4acd-aca4-490cfcdae73b" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | Active Scanning: Directory Enumeration | T1595.003 | Attacker used directory brute-forcing tools (`gobuster`) against the web app. |
| **Initial Access** | Exploit Public-Facing Application | T1190 | Injected malicious XSS payloads into input fields (`/reviews.php`). |
| **Credential Access** | Steal Web Session Cookie | T1539 | Stole legitimate administrator `PHPSESSID` via client-side script execution. |
| **Privilege Escalation** | Session Hijacking | T1563 | Replaced session context with stolen admin token to gain elevated portal access. |
| **Collection / Discovery** | File and Directory Discovery: Path Traversal | T1083 | Exploited path traversal in `/log_viewer.php` using `../../../../etc/passwd`. |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Attacker IP Address:** `111.224.180.128`
* **Admin IP Address:** `135.143.142.5`
* **Web Server IP Address:** `73.124.17.52`
* **Brute-Forcing User-Agent Tool:** `gobuster`
* **Vulnerable Input Endpoint:** `/reviews.php`
* **Stolen Admin PHPSESSID Token:** `lqkctf24s9h9lg67teu8uevn3q`
* **Exploited Script:** `log_viewer.php`
* **Path Traversal Payload:** `file=../../../../../etc/passwd`

---

## 4. Detailed Investigation Walkthrough

### Phase 1: Attacker Identification & Reconnaissance
* **IP Correlation:** Navigated to `Statistics -> Conversations -> IPv4` in Wireshark. Identified three key IP addresses: the Web Server (`73.124.17.52`), Admin (`135.143.142.5`), and the Attacker (`111.224.180.128`).
* **Enumeration Tool:** Filtered HTTP requests by the attacker's IP (`ip.src == 111.224.180.128 and http`). Inspected `User-Agent` headers in initial bursts to identify automated scanning via **`gobuster`**.

### Phase 2: Stored XSS & Admin Token Compromise
* **Script Injection:** Attacker sent POST requests targeting `/reviews.php` containing embedded JavaScript code designed to exfiltrate cookies upon page rendering.
* **Admin Incident Timeline:** Filtered HTTP traffic from the admin IP accessing the infected page:
  `ip.src == 135.143.142.5 and http contains "reviews.php"`.
  Determined the exact UTC timestamp when the administrator visited `/reviews.php`.
* **Session Cookie Extraction:** Followed the HTTP Stream of the admin's packet to locate the stolen `PHPSESSID` header value: **`lqkctf24s9h9lg67teu8uevn3q`**.

### Phase 3: Session Hijacking & Path Traversal
* **Attacker Impersonation:** Applied Wireshark filter to monitor the attacker using the hijacked admin token:
  `ip.src == 111.224.180.128 and frame contains "lqkctf24s9h9lg67teu8uevn3q"`.
* **Vulnerability Exploitation:** Traced subsequent requests to the administrative panel script **`log_viewer.php`**.
* **Payload Verification:** Extracted the malicious URI parameter value: `file=../../../../../etc/passwd` confirming Arbitrary File Read / Path Traversal execution.

---

## 5. Remediation & Defense Recommendations
1. **Input Sanitization & Output Encoding:** Implement strict HTML entity encoding on user submission fields (`/reviews.php`) to neutralize XSS payload execution.
2. **Cookie Security Flags:** Enforce `HttpOnly` and `SameSite=Strict` flags on all session cookies (`PHPSESSID`) to prevent JavaScript access via client-side scripts.
3. **Path Traversal Mitigation:** Sanitize file path parameters in `/log_viewer.php` using whitelisting algorithms and `basename()` checks to eliminate directory traversal.
