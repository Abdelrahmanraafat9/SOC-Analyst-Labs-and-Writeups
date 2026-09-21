# 🔍 Incident Response Report: Tomcat Takeover PCAP Investigation

- **Platform:** CyberDefenders
- **Category:** Network Forensics / Web Server Forensics
- **Difficulty:** Easy / Medium
- **Tools Used:** Wireshark
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An alert was raised regarding anomalous admin dashboard access and unauthorized file upload activity on an internal **Apache Tomcat** web server. 

Full packet capture (`Tomcat-Takeover.pcap`) triage using Wireshark revealed an attacker executing an HTTP Basic Authentication **Brute-Force attack** against the Tomcat Manager interface (`/manager/html`). Upon successfully identifying valid credentials (`tomcat:s3cret`), the attacker leveraged Manager deployment privileges to upload a weaponized **WAR payload** (`zx.war` / `cmd.jsp`) disguised as an application package. The attacker then interacted with the deployed Web Shell to execute arbitrary OS-level commands on the compromised host.

---

<img width="1268" height="596" alt="Screenshot 2026-09-21 173057" src="https://github.com/user-attachments/assets/54608f58-4af1-406e-bdfd-7e462c2bef19" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Brute Force: Password Guessing | T1110.001 | Automated HTTP Basic Auth brute-forcing against Tomcat `/manager/html`. |
| **Initial Access** | Valid Accounts: Local Accounts | T1078.003 | Authenticated to Manager panel using discovered valid credentials. |
| **Persistence / Execution** | Web Shell Deployment via Application Packaging | T1505.003 | Uploaded malicious `.war` archive containing JSP webshell (`cmd.jsp`). |
| **Execution** | Command and Scripting Interpreter: Unix Shell | T1059.004 | Executed arbitrary OS commands via Web Shell HTTP GET parameters. |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Attacker IP Address:** `14.0.0.120`
* **Victim Server IP Address:** `10.0.0.112`
* **Target Web Application:** Apache Tomcat Manager (`/manager/html`)
* **Cracked Credentials:** `tomcat:s3cret` (Base64: `dG9tY2F0OnMzY3JldA==`)
* **Uploaded Payload Name:** `zx.war`
* **Web Shell File:** `cmd.jsp`
* **C2 / Execution URI:** `/zx/cmd.jsp?cmd=[OS_Command]`

---

## 4. Detailed Investigation Walkthrough

### Phase 1: Traffic Overview & Brute-Force Detection
* **Traffic Filter:** Applied `http.request.method == "GET"` and inspected HTTP status codes (`401 Unauthorized`).
* **Pattern Recognition:** Filtered `http.authbasic` in Wireshark to isolate repeated login attempts targeting `/manager/html`. Identified hundreds of HTTP 401 responses originating from attacker IP **`14.0.0.120`**.

### Phase 2: Credential Compromise & Session Authentication
* **Successful Login:** Identified the single successful HTTP response (`200 OK`) following the stream of 401s.
* **Header Decoding:** Inspected the `Authorization: Basic dG9tY2F0OnMzY3JldA==` header. Decoded the Base64 payload in Wireshark / CyberChef to reveal cracked credentials: **`tomcat:s3cret`**.

### Phase 3: Web Shell Deployment (.WAR Upload)
* **Upload Inspection:** Filtered HTTP POST requests: `http.request.method == "POST"`.
* **Payload File Identification:** Located the multipart/form-data request deploying **`zx.war`** to `/manager/html/upload`.
* **Extracting Shell Artifacts:** Examined the HTTP stream to verify the embedded JSP file **`cmd.jsp`** inside the archive.

### Phase 4: Remote Code Execution (RCE) Investigation
* **Web Shell Interaction:** Filtered requests directed towards `/zx/cmd.jsp`.
* **Command Extraction:** Inspected the `cmd` GET parameter in subsequent HTTP requests to trace attacker actions (e.g., `id`, `whoami`, system reconnaissance commands).

---

## 5. Remediation & Defense Recommendations
1. **Manager Interface Hardening:** Restrict access to `/manager/html` via IP whitelisting in `context.xml` or disable public access entirely.
2. **Strong Password Policy:** Enforce complex administrative passwords for `tomcat-users.xml` to prevent dictionary and brute-force attacks.
3. **Account Lockout:** Configure `LockOutRealm` in Tomcat to lock accounts after repeated failed login attempts.
4. **Endpoint / File Integrity Monitoring:** Monitor web directories (`/webapps/`) for unauthorized `.war` and `.jsp` deployments.
