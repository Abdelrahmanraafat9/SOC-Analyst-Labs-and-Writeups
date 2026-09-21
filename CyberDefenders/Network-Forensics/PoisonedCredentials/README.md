# 🔍 Incident Response Report: PoisonedCredentials PCAP Investigation

- **Platform:** CyberDefenders
- **Category:** Network Forensics / Protocol Poisoning
- **Difficulty:** Easy / Medium
- **Tools Used:** Wireshark
- **Analyst:** Abdelrahman Raafat
- **LinkedIn:** [Abdelrahman Raafat](https://www.linkedin.com/in/abdelrahman-raafat-sec/)

---

## 1. Executive Summary & Incident Scenario
An internal network alert reported suspicious broadcast traffic and potential credential harvesting attempts occurring on the corporate local subnet.

Full packet capture analysis (`PoisonedCredentials.pcap`) via Wireshark revealed an attacker machine operating a poisoning tool (such as Responder) on the LAN. When a victim host attempted to locate an unresolvable network resource, it broadcasted **LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)** requests. The rogue machine responded with spoofed authoritative responses, forcing the victim machine to attempt SMB/HTTP authentication against the attacker's fake service. Consequently, NTLMv2 password hashes (`NTLMv2-SSP`) for domain accounts were intercepted and exfiltrated to the attacker.

---

<img width="1267" height="460" alt="Screenshot 2026-09-21 173527" src="https://github.com/user-attachments/assets/4d9c3292-9cf9-4c4d-b91e-68fd819f9cf0" />


## 2. Threat Classification & MITRE ATT&CK Mapping
| Tactic | Technique | ID | Technical Description |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning | T1557.001 | Spoofed resolution responses to capture NTLM authentication attempts. |
| **Credential Access** | Steal or Forge Kerberos / NTLM Hashes | T1558 | Harvested NTLMv2 challenge-response hashes from victim connection attempts. |
| **Reconnaissance** | Network Service Discovery | T1046 | Listened to multicast/broadcast queries across UDP ports 5355 (LLMNR) and 137 (NBT-NS). |

---

## 3. Verified Indicators of Compromise (IoCs)
* **Poisoner / Rogue Machine IP:** Attacker local host IP identified in LLMNR/NBT-NS response packets.
* **Victim Host IP:** Workstation sending unresolved UDP broadcast requests.
* **Target Protocols:** LLMNR (UDP 5355), NBT-NS (UDP 137), SMB (TCP 445).
* **Compromised Data Type:** NTLMv2 Challenge/Response Hashes (User domain credentials).
* **Requested Non-Existent Share/Resource:** Unresolved SMB share name broadcasted by victim.

---

## 4. Detailed Investigation Walkthrough

### Phase 1: Identifying Broadcast Queries & Poisoned Responses
* **Wireshark Filter:** `llmnr or nbns`
* **Query Analysis:** Located UDP queries directed to multicast destination addresses (`224.0.0.252` for LLMNR) searching for non-existent local machine names.
* **Rogue Host Identification:** Observed immediate unicast responses originating from the rogue IP answering with its own IP address as the destination for the requested resource.

### Phase 2: NTLM Challenge/Response Capture
* **Wireshark Filter:** `ntlmssp` or `smb2.cmd == 1`
* **Authentication Interception:** Filtered SMB2 Session Setup requests following the poisoned DNS resolution.
* **Hash Verification:** Inspected the `NTLMSSP_AUTH` packet structures containing the domain name, username, target server name, dynamic client challenge, and NTLMv2 response blobs.

### Phase 3: Blast Radius Assessment
* **Correlating Victims:** Filtered unique source IPs sending LLMNR/NBT-NS traffic to identify all endpoints impacted by the rogue responder during the capture window.

---

## 5. Remediation & Defense Recommendations
1. **Disable LLMNR & NBT-NS:** Enforce Group Policy Objects (GPOs) to completely disable LLMNR (`Turn off Link-Local Multicast Name Resolution`) and NetBIOS over TCP/IP across all Windows clients.
2. **Enable SMB Signing:** Require mandatory SMB Signing (`RequireSecuritySignature`) on all network hosts to neutralize NTLM relay attacks.
3. **Network Segmentation & Dynamic ARP Inspection:** Implement Network Access Control (NAC) and isolation policies to prevent unauthorized rogue devices from joining local VLANs.
4. **Credential Hardening:** Enforce strong password complexity and rotate credentials for accounts whose NTLMv2 hashes were exposed.
