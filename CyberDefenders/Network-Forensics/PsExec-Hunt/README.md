# 🔍 Incident Response Report: PsExec Hunt PCAP Investigation

- **Platform:** CyberDefenders
- **Category:** Network Forensics / Lateral Movement
- **Difficulty:** Medium
- **Tools Used:** Wireshark
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An internal SOC alert triggered regarding potential unauthorized administrative activity and lateral movement across internal subnets. 

Full packet capture analysis (`psexec.pcap`) via Wireshark confirmed that an attacker utilized stolen domain credentials to execute lateral movement from a workstation (`192.168.1.100`) to a critical server (`192.168.1.10`) via SMB/RPC (Port 445). The attacker authenticated using SMB Session Setup, mounted administrative shares (`ADMIN$`, `C$`), transferred the remote execution wrapper service (`PSEXESVC.exe`), created a Windows service dynamically via DCE/RPC (`svcctl`), and executed privileged arbitrary commands on the target host.

---

<img width="1223" height="646" alt="Screenshot 2026-09-21 173305" src="https://github.com/user-attachments/assets/4d3fadbe-46d6-4ed9-8bff-6e50a8381e67" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Valid Accounts: Domain Accounts | T1078.002 | Authenticated via NTLMv2 SSP over SMB to target host. |
| **Lateral Movement** | Service Execution: PsExec | T1021.002 | Leveraged Sysinternals PsExec pattern to connect to `ADMIN$` share. |
| **Persistence / Execution** | System Services: Service Execution | T1543.003 | Created and started `PSEXESVC` via Service Control Manager (`svcctl`). |
| **Command & Control** | Sub-technique: Named Pipes | T1090 | Created named pipes (`\pipe\psexecsvc`) for stdin/stdout/stderr redirect. |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Source Host (Attacker IP):** `192.168.1.100`
* **Target Host (Victim IP):** `192.168.1.10`
* **Target Administrative Shares:** `ADMIN$`, `C$`
* **Service Executable Dropped:** `PSEXESVC.exe`
* **Service Name Created:** `PSEXESVC`
* **Service Control Manager RPC Pipe:** `\pipe\svcctl`
* **PsExec Named Pipes:** `\pipe\psexecsvc-CLIENT-stdin`, `\pipe\psexecsvc-CLIENT-stdout`

---

## 4. Detailed Investigation Walkthrough

### Phase 1: SMB Traffic & Authentication Triage
* **Wireshark Filter:** `smb2 or smb`
* **Authentication Triage:** Filtered `smb2.cmd == 1` (Session Setup Request) to isolate authentication frames. Identified NTLM SSP authentication originating from `192.168.1.100` targeting `192.168.1.10`.

### Phase 2: Administrative Share Access & File Drop
* **Wireshark Filter:** `smb2.tree` or `smb2.filename`
* **Share Connection:** Located Tree Connect requests targeting administrative share `\\192.168.1.10\ADMIN$`.
* **Payload Drop:** Inspected SMB Create / Write operations to verify the transfer of binary file **`PSEXESVC.exe`** onto the `C:\Windows\` directory of the target machine.

### Phase 3: Service Creation via DCE/RPC (`svcctl`)
* **Wireshark Filter:** `dcerpc` or `dcerpc.svcctl`
* **Service Manager Binding:** Traced DCE/RPC traffic establishing a pipe bind to `\pipe\svcctl` (Service Control Manager).
* **CreateService & StartService Calls:** Analyzed `CreateServiceW` and `StartServiceW` requests where the service `PSEXESVC` was registered to point to `%SystemRoot%\PSEXESVC.exe`.

### Phase 4: Command Execution via Named Pipes
* **Wireshark Filter:** `smb2.filename contains "pipe"`
* **Communication Channels:** Identified the creation of bidirectional named pipes used by PsExec to route stdin, stdout, and stderr between the source client and target host.

---

## 5. Remediation & Defense Recommendations
1. **Restrict SMB Lateral Movement:** Block TCP Port 445 between workstation subnets using local firewalls and host isolation policies.
2. **Disable Administrative Shares:** Enforce GPOs to restrict default administrative shares (`ADMIN$`, `C$`) on endpoints where not required.
3. **Privileged Account Management (PAM):** Restrict local administrator password reuse across hosts by deploying Microsoft LAPS.
4. **EDR Rules & Behavioral Detection:** Implement detection alerts for execution of binaries matching `PSEXESVC.exe` or dynamic creation of services via `svcctl`.
