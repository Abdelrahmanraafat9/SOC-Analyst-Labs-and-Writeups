# 🔍 Incident Response Report: BlackEnergy Memory Forensics

- **Platform:** CyberDefenders
- **Category:** Memory Forensics / Malware Analysis
- **Difficulty:** Medium
- **Tools Used:** Volatility 2, Volatility 3
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An incident response investigation was conducted on a Windows memory dump (`Victim.raw` / `BlackEnergy.raw`) following reports of critical infrastructure compromise. 

Using **Volatility 2/3**, deep memory analysis was performed to trace the execution of the **BlackEnergy** Trojan/rootkit. The triage revealed malicious code injection into core Windows processes (such as `svchost.exe` and `lsass.exe`), unauthorized driver loadings (`msx64.sys` / kernel hooks), hidden registry persistence, and active network connections back to C2 servers.

---
<img width="1468" height="665" alt="Screenshot 2026-09-21 173914" src="https://github.com/user-attachments/assets/5e774b33-9b33-486b-9eee-4f1f173ef359" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Defense Evasion** | Process Injection | T1055 | Injected shellcode/DLL payloads into unbacked `svchost.exe` memory regions. |
| **Persistence** | Rootkit / Kernel Modules | T1014 | Loaded malicious kernel driver (`msx64.sys`) to hide files and network ports. |
| **Discovery** | Process Discovery | T1057 | Evaluated process tree hierarchy to identify abnormal parent-child PID relations. |
| **Command & Control** | Web Protocols: HTTP/HTTPS | T1071.001 | Established C2 beacons from injected memory spaces to exfiltrate host info. |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Injected Core Process:** `svchost.exe` (Parent PID anomaly)
* **Malicious Kernel Driver / Service:** `msx64.sys`
* **Volatility OS Profile:** `WinXPSP2x86` / `WinXPSP3x86`
* **Injected Memory Allocation:** Memory pages with `PAGE_EXECUTE_READWRITE` (RWX) permissions lacking disk backing.
* **C2 Communication Port:** Custom HTTP / TCP sockets identified via netscan/connscan.

---

## 4. Detailed Investigation Walkthrough

### Phase 1: OS Image Profiling & Process Tree Analysis
* **Volatility Plugin:** `imageinfo` / `windows.info`
  Identified the target operating system profile to execute accurate Volatility plugins.
* **Volatility Plugin:** `pstree` / `pslist` / `psxview`
  Evaluated all active processes. Cross-examined `psxview` to discover hidden or unlinked processes hidden by rootkit hooks (`pslist` vs `psscan` discrepancies).

### Phase 2: Detecting Injection & Malicious DLLs
* **Volatility Plugin:** `malfind`
  Scanned process memory spaces for executable pages (`PAGE_EXECUTE_READWRITE`). Identified injected shellcode and VAD (Virtual Address Descriptor) tags in `svchost.exe`.
* **Volatility Plugin:** `dlllist` / `ldrmodules`
  Checked for unlinked DLLs within the PEB (Process Environment Block) to spot injected or unbacked dynamic libraries.

### Phase 3: Kernel Module & Rootkit Analysis
* **Volatility Plugin:** `modules` / `modscan` / `ssdt`
  Scanned for rogue drivers. Located `msx64.sys` driver loaded outside standard `System32\drivers` paths and detected hooked System Service Descriptor Table (SSDT) entries.

### Phase 4: Artifact Extraction & Payload Dumping
* **Volatility Plugin:** `procdump` / `dlldump` / `vaddump`
  Dumped the injected memory regions and binaries for static triage and cryptographic hashing.

---

## 5. Remediation & Defense Recommendations
1. **Host Isolation & Re-imaging:** Isolate affected endpoints immediately and perform full OS re-imaging to eliminate rootkit and kernel driver modifications.
2. **EDR & Memory Integrity Guards:** Enable Credential Guard, Device Guard, and EDR Driver Signature Enforcement (DSE) to block unsigned driver loading (`msx64.sys`).
3. **Network Perimeter Blocking:** Sinkhole outbound C2 IP addresses and domain endpoints identified in memory network scans.
