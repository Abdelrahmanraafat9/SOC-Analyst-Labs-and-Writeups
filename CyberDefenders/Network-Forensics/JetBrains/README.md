# 🔍 Incident Response Report: JetBrains Lab

- **Platform:** CyberDefenders
- **Category:** Network Forensics
- **Difficulty:** Easy
- **Tools Used:** Wireshark, NetworkMiner
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary
During a security monitoring session, an alert indicated a potential compromise on the web server running JetBrains TeamCity. Analysis of the network traffic capture (PCAP) confirmed that an external attacker exploited a vulnerability to execute unauthorized commands, upload a malicious webshell (`NSt8bHTg.zip` containing a `.jsp` shell), and attempt local user credential tampering and container escape.

---
<img width="1247" height="648" alt="Screenshot 2026-09-21 171648" src="https://github.com/user-attachments/assets/5c55c9b5-ef8b-4d6f-a32d-8e5db7e78891" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Exploit Public-Facing Application | T1190 | Exploited TeamCity Web Server vulnerability |
| **Persistence / Execution** | Web Shell | T1505.003 | Uploaded malicious JSP webshell via `/admin/pluginUpload.html` |
| **Credential Access / Defense Evasion** | Modify System Image / Files | T1070 | Tampered with administrative credential files |
| **Privilege Escalation** | Escape to Host | T1611 | Attempted Docker container escape using root mount |

---

## 3. Indicators of Compromise (IoCs)
* **Attacker Source IP:** `23.158.56.196`
* **Uploaded Web Shell File:** `NSt8bHTg.zip` (Extracted to JSP shell)
* **Exploited Endpoint:** `/admin/pluginUpload.html` / `/app/rest/server`
* **Container Escape Command:** `docker run --rm -it -v /:/host ubuntu chroot /host`

---

## 4. Investigation & Walkthrough

### Q1: What is the attacker's IP address?
* **Filter Used:** `http.request.method == POST`
* **Analysis:** Filtered for POST traffic in Wireshark to locate file upload behavior. Observed requests to `/admin/pluginUpload.html` originating from `23.158.56.196`.

### Q2: What version of our web server service is running?
* **Analysis:** Inspected HTTP responses and server headers from the target server.

### Q3: What CVE number corresponds to the vulnerability exploited?
* **Analysis:** Researched the TeamCity version vulnerability (Authentication Bypass / Unauthenticated RCE).

### Q4: What credentials did the attacker set up after exploiting the vulnerability?
* **Analysis:** Analyzed HTTP parameters in authentication POST requests made during the exploit chain.

### Q5: What is the name of the webshell file uploaded by the attacker?
* **Analysis:** Inspected multipart POST body parameters to find the uploaded plugin archive (`NSt8bHTg.zip`).

---

## 5. Recommended Mitigation Steps
1. **Patch Management:** Immediately update JetBrains TeamCity to the latest patched version.
2. **Network Segmentation & Firewall:** Block traffic from identified attacker IP (`23.158.56.196`) on perimeter devices.
3. **Container Hardening:** Disable privileged flag execution on Docker containers to prevent `/host` root file system mounting attempts.
4. **Credential Reset:** Rotate all admin and system service credentials immediately.
