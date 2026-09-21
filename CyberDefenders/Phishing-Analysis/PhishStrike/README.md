# 🔍 Incident Response Report: PhishStrike Email Analysis

- **Platform:** CyberDefenders
- **Category:** Threat Intelligence / Phishing Analysis
- **Difficulty:** Easy / Medium
- **Tools Used:** Email Header Analyzer / MXToolbox, URLhaus, VirusTotal, Any.Run, CyberChef
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An alert was triggered within an educational institution's SOC after faculty members received a targeted spear-phishing email claiming a **$625,000 purchase**. The email pretended to come from a trusted contact and embedded a link to download a fake invoice. 

Detailed email header and threat intelligence triage confirmed that the email spoofed authentic domains (SPF softfail / DKIM fail). The embedded URL delivered dynamic malware payloads including **BitRAT**, **AsyncRAT**, and **CoinMiner**. The payloads establish persistence via Windows Run Registry keys, introduce evasion execution delays via PowerShell, and leverage Telegram Bots for C2/data exfiltration.

---

<img width="1262" height="665" alt="Screenshot 2026-09-21 171937" src="https://github.com/user-attachments/assets/f2191921-23e0-4447-b9c0-e05e3260fe53" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Spearphishing Link | T1566.002 | Embedded malicious URL inside the email body pointing to payload delivery IP. |
| **Defense Evasion** | Email Authentication Bypass | T1566 | Forged sender headers bypassing SPF/DKIM validation mechanisms. |
| **Persistence** | Registry Run Keys / Startup | T1547.001 | Added executable entry (`Jzwvix.exe`) to `HKCU\...\CurrentVersion\Run`. |
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497 | Encoded PowerShell command executing a `Start-Sleep` (50s) delay before detonation. |
| **Command & Control** | Exfiltration Over Web Service | T1071.001 | Utilized Telegram Bot API for exfiltrating stolen host metrics. |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Spoofed Sender IP:** `18.208.22.104` (SPF: softfail / DKIM: fail)
* **Return-Path Address:** `erikajohana.lopez@uptc.edu.co`
* **Malware Hosting IP:** `107.175.247.199`
* **BitRAT Persistence Executable:** `Jzwvix.exe`
* **BitRAT Payload Hash (SHA-256):** `bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539`
* **Evasion Delay:** `50` seconds via Base64-decoded PowerShell
* **Telegram Bot C2 ID:** `bot5610920260`

---

## 4. Detailed Investigation Walkthrough

### Phase 1: Header Triage & Authentication Verification
* **Sender IP & Auth:** Analyzed the raw MIME headers using MXToolbox / Email Header Analyzer. The originating IP **`18.208.22.104`** generated an `SPF: softfail` and `DKIM: fail`, confirming domain spoofing.
* **Return-Path Extraction:** Discovered the actual bounce address in the `Return-Path` header specified as **`erikajohana.lopez@uptc.edu.co`**.

### Phase 2: Malicious Link & Payload Delivery
* **Payload Host:** Extracted the invoice link pointing to hosting IP **`107.175.247.199`**.
* **Malware Taxonomy:** Searching URLhaus / MalwareBazaar revealed the link delivered multiple malware families, specifically **Coinminer** for cryptocurrency resource abuse, **BitRAT**, and **AsyncRAT**.

### Phase 3: Sandbox Analysis & Evasion (Any.Run / CyberChef)
* **Persistence Mechanism:** Sandbox analysis of the BitRAT payload (`bf7628695c2df7a...`) confirmed it dropped **`Jzwvix.exe`** into the auto-run registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
* **Evasion Script Decoding:** Extracted an encoded PowerShell execution. Base64 decoding via CyberChef revealed a `Start-Sleep -s 50` command used to delay execution by **50 seconds** to evade automated sandbox detonation windows.
* **C2 Communication Channels:** Traced network traffic showing AsyncRAT/BitRAT utilizing Telegram Bot API infrastructure (**`bot5610920260`**) for C2 operations.

---

## 5. Remediation & Incident Response Actions
1. **Gateway Rules:** Blacklist IP `107.175.247.199` and `18.208.22.104` across perimeter Firewalls and Email Gateways.
2. **Mailbox Purge:** Run PowerShell/Exchange compliance searches to delete all emails matching Return-Path `erikajohana.lopez@uptc.edu.co`.
3. **Endpoint Hunting:** Query EDR telemetry for process executions of `Jzwvix.exe` and registry changes under `HKCU\...\CurrentVersion\Run`.
4. **Network Blocking:** Sinkhole outbound traffic requesting Telegram Bot ID endpoints (`bot5610920260`).
