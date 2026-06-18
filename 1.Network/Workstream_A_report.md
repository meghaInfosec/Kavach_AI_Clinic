# Network Forensics Report — Workstream A
**Project KAVACH | Client: Meridian FinServe Pvt. Ltd.**
**PCAP Analyzed:** `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap`

---

## 1. Executive Summary

During the analyzed capture window (80 minutes 9 seconds), an internal workstation (`10.5.26.132`, hostname `DESKTOP-OG16DGY`) was compromised by the Trickbot malware family. Within minutes of infection, the malware established encrypted command-and-control (C2) communication with multiple external servers, performed reconnaissance of its public IP address, and exfiltrated system/credential data to attacker-controlled infrastructure.

Approximately 13 minutes into the incident, the attacker pivoted from the infected workstation to the Domain Controller (`10.5.26.4`, `VICTORYPUNK-DC`) using Windows service-creation techniques (SMB/svcctl — a PsExec-style method). Once the DC was compromised, it also began beaconing to Cobalt Strike infrastructure and exfiltrating harvested data, while simultaneously being used to probe five additional internal workstations over SMB — indicating an attempt at network-wide spread.

No evidence of detection or containment was observed during the 80-minute window; the primary C2 beacon was still active at the moment the capture ended.

**Overall Severity: HIGH** — Full domain compromise achieved (workstation → Domain Controller), with active C2 channels, credential harvesting, and lateral movement, all unmitigated.

---

## 2. Scope & Methodology

| Field | Value |
|---|---|
| PCAP File | `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap` |
| File Size | 17 MB |
| Total Packets | 26,644 |
| Capture Duration | 4,809.71 seconds (~80 min 9 sec) |
| Capture Window | 2021-05-26 20:23:18 → 21:43:28 UTC |
| SHA-256 | `fee3f9a285ab295821a7452a80cfaab25b8ccc60ad39052547ec67c8c3c9ca1e` |
| Internal Subnet | 10.5.26.0/24 |
| Internal Domain | victorypunk.com |
| Tools Used | tshark (CLI), Wireshark (GUI) |
| Analysis Approach | Baseline-first triage (protocol distribution, endpoints, conversations, top talkers, time bounds, burst analysis) followed by hypothesis-driven deep dive |

All findings below were independently re-verified against the source PCAP using live `tshark`/`capinfos` queries; no discrepancies were found.

---

## 3. Timeline of Events

| Time (Capture-Relative) | Event | Significance |
|---|---|---|
| T+0s (20:23:18) | Capture begins; `10.5.26.132` receives DHCP lease | Baseline established |
| T+106s (20:25:04) | First connection to `37.228.70.134:443`, no TLS SNI | Cobalt Strike beacon initialized |
| T+107s (20:25:05) | Workstation queries `api.ipify.org` | Pre-exfiltration public-IP reconnaissance |
| T+370s (20:29:28) | Workstation POSTs 4,911 bytes to `/rob87/DESKTOP-OG16DGY_.../90` (36.95.27.243) | First data exfiltration (Trickbot gtag `rob87`) |
| T+391s | Same payload re-sent to backup C2 (`103.102.220.50`) | C2 redundancy confirmed |
| T+484s | Workstation issues `svcctl` (Service Control) calls to DC (`10.5.26.4`) | PsExec-style lateral movement begins |
| T+783s (20:36:21) | DC POSTs 4,736 bytes to `/tot108/VICTORYPUNK-DC_.../90` | Domain Controller compromised; lateral movement succeeded |
| T+854s | DC queries `myexternalip.com/raw` | Second-stage IP reconnaissance (post-DC compromise) |
| T+4,212s onward | DC sends 16 POST bursts to `5.199.162.3/as` (up to 10,336 bytes) | Bulk credential/data harvesting transfer |
| T+4,749s | Final beacon to `37.228.70.134:443` (still no SNI) | C2 channel remains active at capture end |
| T+4,809s (21:43:28) | Capture ends | Intrusion ongoing, undetected |

---

## 4. Key Findings

### 4.1 Triage Baseline
- Protocol distribution showed HTTP at only 1.08% of frames but 41.2% of bytes — a strong anomaly indicating large payload transfers disguised as web traffic.
- Top external endpoint: `192.236.155.230` (~7.4 MB transferred) — identified as the primary Trickbot C2 server.
- Heaviest internal↔external session: `10.5.26.4 ↔ 192.236.155.230` (4 MB across 3,810 packets).
- Two traffic burst windows (300–900s) carried ~10× baseline volume, corresponding to payload delivery and Cobalt Strike onset.
- Two near-identical HTTP/80 traffic spikes (~T+400s and ~T+800s) indicated periodic, machine-driven C2 check-ins.

### 4.2 Command & Control (C2) Beaconing — CONFIRMED, High Confidence
- Connection from `10.5.26.132` to `37.228.70.134:443` repeated at consistent ~202-second intervals across 28 sessions.
- All 28 TLS ClientHello packets to this IP carried an empty SNI field — consistent with Cobalt Strike's default malleable C2 behavior.
- Beaconing was active from T+106s through T+4,749s — spanning nearly the entire capture, with no interruption.
- Additional confirmed Cobalt Strike beacon channels (no-SNI HTTPS, ~207s interval): `91.83.88.122` (from `10.5.26.132`) and `45.229.71.211` (from `10.5.26.4`).

### 4.3 Data Exfiltration — CONFIRMED, High Confidence
- First exfiltration event at T+370s: a 4,911-byte HTTP POST from `10.5.26.132` to `36.95.27.243`, with URI path `/rob87/DESKTOP-OG16DGY_W617601.D5D933B2E59558F3F46D9130BB091D98/90` — the hostname and a build-specific hash are embedded directly in the URI.
- Identical payload re-sent to a secondary C2 (`103.102.220.50`), confirming redundant exfiltration infrastructure.
- After DC compromise, `10.5.26.4` repeated the same pattern under Trickbot gtag `tot108`.
- Both infected hosts performed public-IP reconnaissance (via `api.ipify.org`, `ipinfo.io`, `myexternalip.com`, `api.ip.sb`) immediately prior to exfiltration — a structured pre-exfiltration recon sequence.
- A secondary exfiltration channel to `5.199.162.3/as` (hosting `antivirusupdaty.com`) transferred 16 separate POST bursts late in the capture, totaling tens of kilobytes of harvested data.

### 4.4 Lateral Movement — CONFIRMED, High Confidence
- At T+484s, `10.5.26.132` initiated `svcctl` (Windows Service Control Manager RPC) calls against the Domain Controller `10.5.26.4` — the classic PsExec remote-execution technique.
- The DC began exfiltrating data 7 minutes later (T+783s), confirming successful compromise via this path.
- A 1.79 MB SMB session (port 445) between the workstation and DC, with the DC returning 1.67 MB to the workstation, is consistent with payload/module delivery following service installation.
- All five remaining internal workstations (`10.5.26.130`, `.134`, `.136`, `.138`, `.140`) received SMB connection attempts from the DC (110–150 packets each), indicating a network-wide spreading attempt beyond the initial two hosts.

---

## 5. Indicators of Compromise (IOC) Summary

*(Full machine-readable list in `iocs.csv` — 50+ entries)*

| Category | Indicators |
|---|---|
| C2 IPs (High Confidence) | 192.236.155.230, 36.95.27.243, 103.102.220.50, 78.186.110.14, 91.83.88.122, 45.229.71.211, 37.228.70.134, 5.199.162.3 |
| C2 Domains | antivirusupdaty.com |
| Recon Domains | api.ip.sb, api.ipify.org, myexternalip.com, ipinfo.io |
| Malicious URI Patterns | `/rob87/<host>_<build>.<hash>/90`, `/tot108/<host>_<build>.<hash>/90`, `/images/redbutton.png`, `/images/cutscroll.png`, `/ico/viodifot`, `/as`, `/logo?hour=true` |
| Suspicious User-Agents | `WinHTTP loader/1.0`, `Winhttp 1/0`, fake Android UA (Cobalt Strike), `curl/7.69.1`, `curl/7.74.0`, `curl/7.76.0` |
| Compromised Hosts | `DESKTOP-OG16DGY` (10.5.26.132, Patient Zero), `VICTORYPUNK-DC` (10.5.26.4, Domain Controller) |
| Trickbot Identifiers | gtags `rob87` (workstation), `tot108` (DC); build ID `W617601` |

---

## 6. Network Architecture Findings

**Current (As-Observed) State:**
The environment had no meaningful defence-in-depth: outbound traffic on ports 80, 443, and 447 was unrestricted; no DNS firewall blocked resolution of malicious domains; the LAN was flat with no east-west segmentation, allowing the DC unrestricted SMB access to all workstations; and no SIEM/NDR was present to detect the 80-minute intrusion.

**Proposed Hardened State:**
A four-layer remediation model is proposed — Identity (MFA + PAM), Perimeter (egress allowlisting + DNS firewall + WAF), Segmentation (VLAN-based microsegmentation with default-deny east-west policy), and Observability (Suricata/Zeek-based NDR feeding a SIEM pipeline). Each control is directly mapped to a specific IOC or gap identified in this analysis (see `architecture/before.svg` and `architecture/after.svg`).

Projected impact: detection time reduced from ~80 minutes to under 5 minutes; C2 beaconing and the port-447 exfiltration channel blocked at the perimeter; lateral movement contained within VLAN boundaries.

---

## 7. Business Impact (Meridian FinServe Context)

As a financial services entity, Meridian FinServe's compromise of its Domain Controller represents a critical-severity event with the following implications:

- **Credential Exposure:** Domain-wide credential harvesting via a compromised DC could enable access to core banking applications, customer databases, and privileged accounts.
- **Regulatory Exposure:** A confirmed DC compromise with data exfiltration may trigger mandatory breach notification obligations under applicable financial-sector regulations (e.g., RBI cybersecurity directives, PCI-DSS for any cardholder data environments).
- **Operational Risk:** Continued, undetected C2 access provides the attacker persistent capability to disrupt core services or stage further attacks (ransomware deployment is a common Trickbot/Cobalt Strike follow-on).
- **Reputational Risk:** Disclosure of a domain-wide compromise at a financial institution carries significant client-trust implications.

---

## 8. Recommendations

| Priority | Recommendation | Rationale |
|---|---|---|
| Immediate | Isolate `10.5.26.132` and `10.5.26.4` from the network; rotate all domain credentials | Active C2 channels and confirmed credential exfiltration |
| Immediate | Block egress to all identified C2 IPs and `antivirusupdaty.com` at the perimeter firewall | Stops ongoing beaconing and exfiltration |
| Short-term | Deploy DNS firewall and egress allowlisting (ports 80/443 only, with TLS SNI inspection) | Detects and blocks no-SNI Cobalt Strike traffic |
| Short-term | Deploy a SIEM/NDR solution (e.g., Suricata + Zeek) with alerting on `svcctl` and unusual SMB patterns | Reduces detection time from ~80 min to <5 min |
| Medium-term | Implement VLAN-based network segmentation with default-deny east-west policy between workstations and the DC | Contains future lateral movement |
| Medium-term | Enforce MFA and Privileged Access Management (PAM) for all administrative and domain accounts | Mitigates impact of credential theft |
| Long-term | Conduct a full Active Directory security review (Kerberos ticket policies, service account hygiene) following this incident | Confirmed AD authentication activity preceded lateral movement |

---

## 9. Appendix / References
- [`Triage/1.triage-wireshark.md`](../A.2%20Triage/1.triage-wireshark.md) — GUI-based baseline triage (6 sections, 12 evidence images)
- [`Triage/2.triage-tshark.md`](../A.2%20Triage/2.%20triage-tshark.md) — CLI triage with 21 reference commands (19 evidence images)
- [`Hypotheses.md`](../A.3%20Hypothesis-Driven%20Deep%20Dive/Hypotheses.md) — Hypothesis-driven deep dive (A.3); source of all timeline/evidence data above
- [`iocs.csv`](../A.4%20Indicator%20Extraction/iocs.csv) — Full machine-readable IOC list
- 📄 [`1.before.mermaid`](https://github.com/meghaInfosec/MKavach/blob/main/1.Network/A.5%20Architecture%20Proposal/1.before.mermaid) — Network as-is, pre-analysis (Mermaid source)
📄 [`2.after.mermaid`](https://github.com/meghaInfosec/MKavach/blob/main/1.Network/A.5%20Architecture%20Proposal/2.after.mermaid) — Proposed hardened architecture (Mermaid source)
- Evidence screenshots: [`./A.2 Triage/Evidences/`](../A.2%20Triage/Evidences/)

---

*Project KAVACH · Workstream A · Network Forensics Report · Futurense AI Clinic × IIT Roorkee · Confidential*
