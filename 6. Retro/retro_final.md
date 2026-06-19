# Project Retrospective — Project KAVACH
**IIT Roorkee × Futurense Technologies · Sprint 2–3 Combined Engagement**
**Format:** Team Retrospective · Post-Engagement Review
**Date:** June 2026

---

## 00. Engagement at a Glance

| Field | Detail |
|-------|--------|
| **Project** | KaVacH — Two-Surface Security Assessment |
| **Client** | Meridian FinServe Pvt. Ltd. *(Fictional NBFC)* |
| **Duration** | 4 iterations × 1 week each |
| **Team** | Megha Sharma · Vinay Kumar · Kedar Pavaskar |
| **Surfaces** | Network Forensics (WS-A) · Web App Assessment (WS-B) · Synthesis (WS-C) |
| **Tooling** | Wireshark · tshark · Semgrep CE · Burp Suite Community · Docker · Mermaid |

---

## 01. Sprint-by-Sprint Review

### Iteration 1 — Frame
**Goal:** Charter freeze · Environment setup · PCAP selection · Threat model v0

| Outcome | Status |
|---------|--------|
| Docker environment (DVWA + Juice Shop) stood up | ✅ |
| PCAP selected and validated | ✅ `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap` |
| Repository structure established | ✅ |
| Threat model v0 drafted | ✅ |
| Environment reproducible in <15 minutes | ✅ |

**Highlight:** Docker compose was clean from day one — DVWA on 8082, Juice Shop on 3000, Metasploitable2 on 2222 — with zero environment conflicts across the team.

---

### Iteration 2 — Network
**Goal:** Workstream A complete through A.4 · Architecture proposal in draft

| Outcome | Status |
|---------|--------|
| A.1 PCAP selection documented | ✅ |
| A.2 Triage — Wireshark + tshark | ✅ |
| A.3 Hypothesis-driven deep dive | ✅ 3 hypotheses confirmed |
| A.4 IOC extraction (CSV) | ✅ 16 rows · tshark-verified |
| A.5 Architecture before/after SVG | ✅ |
| A.6 C2 Beaconing & Data Exfiltration | ✅ tshark-confirmed with frame evidence |

**Key findings confirmed:**
- Cobalt Strike C2 beaconing at ~202s intervals to `37.228.70.134:443`
- Lateral movement via `svcctl` at frame 10799
- Data exfiltration POSTs confirmed via tshark to `36.95.27.243` and `103.102.220.50`
- Second PCAP analysis provided additional corroborating exfiltration evidence

---

### Iteration 3 — Web
**Goal:** Workstream B complete through B.4 · SAST baselines captured

| Outcome | Status |
|---------|--------|
| B.1 Docker environment documented | ✅ |
| B.2 5+ OWASP categories demonstrated | ✅ A01 · A02 · A03 (SQLi + XSS) · A04 · A07 |
| B.3 Attack path documentation | ✅ |
| B.4 SAST — Semgrep CE before/after | ✅ 169 → 168 findings |
| Code-level patches (min 3 required) | ✅ 5 code patches delivered |

**Highlight:** DVWA source patched at all three security levels (low/medium/high) for both SQLi and XSS — not just the low level, which is the typical shortcut.

---

### Iteration 4 — Synthesise
**Goal:** Workstream C complete · Deliverable pack frozen · Retrospective held

| Outcome | Status |
|---------|--------|
| C.1 Joint STRIDE threat model | ✅ KAVACH-WC-TM-001 |
| C.1 Attack chains (3 cross-surface) | ✅ KAVACH-WC-AC-001/002/003 |
| C.2 Defense-in-Depth proposal | ✅ KAVACH-WC-C2-001 |
| C.3 Executive readout (PDF) | ✅ |
| Individual reflections submitted | ✅ Q1–Q8 |
| Repository independently reviewable | ✅ |

---

## 02. KEEP — What Worked Well

### Hypothesis-Driven Forensics
Structuring Workstream A around competing hypotheses with explicit confirm/refute/verdict tests prevented premature anchoring. Each hypothesis required a falsification condition — not just confirmation evidence. The lateral movement hypothesis (H3) is the clearest example: high SMB volume to the DC was consistent with normal domain activity and would have been dismissed without the additional requirement to locate `svcctl` calls specifically at frame 10799.

### tshark-Verified Evidence Chain
Every network finding was backed by a reproducible tshark command returning specific frame numbers. Data exfiltration was confirmed across multiple flows with machine-name-embedded URIs — the `/rob87/` and `/tot108/` patterns — providing a complete, reproducible evidence chain. This is the gold standard for network forensics deliverables.

### Modular Repository Structure
Numbering every deliverable folder and file (`A.1`, `A.2`, `B.1`, `B.2`) made the repository navigable without explanation. An independent reviewer could follow the engagement logic from README alone — exactly as the brief required.

### Docker-First Lab Environment
DVWA, Juice Shop, and Metasploitable2 running on isolated Docker ports eliminated environment inconsistencies. The docker-compose was committed from day one and never changed — any reviewer can reproduce the environment in under 15 minutes.

### Semgrep CE — Static Analysis Integration
Running Semgrep CE with the OWASP top-ten ruleset provided a machine-readable before/after diff, converting subjective remediation claims into quantified evidence. The A04 hardcoded JWT finding (1 → 0 findings) and the global scan reduction (169 → 168) are concrete, auditable proof of remediation effectiveness.

### LLM as Force Multiplier — Not Author
LLMs were used to generate candidate payloads, explain protocol bytes, and draft first-pass prose — not to produce final findings. Every LLM output was verified against the running system or primary source before being written into a deliverable.

### Cross-Surface Synthesis
The Joint Threat Model treated Meridian FinServe as one system, not two. Attack Chain 1 traces frame 10799 (`svcctl` lateral movement) through the surface boundary to the IDOR finding on `/api/statements/{id}` — 1,80,000 borrower records exposed via a credential harvested from DC memory. This cross-surface chain is the core deliverable that differentiates this engagement from two separate assessments.

---

## 03. STOP — What to Leave Behind

### Fixed Iteration Boundaries Without Mid-Sprint Adjustment
The engagement was designed around one-week iterations, but mid-sprint scope expansion — particularly adding additional PCAP corroboration in Iteration 2 and extending SAST patch coverage to all three DVWA security levels — pushed work beyond the planned boundaries. Future engagements benefit from a lightweight mid-sprint check to redistribute scope before it accumulates at the end.<br>

Vague IOC Attribution: Listing IP addresses as indicators without linking them directly to specific packet ranges or confidence scores. All IOCs must be explicitly justified.

---

## 04. START — What to Add Next Time

### Strict Iteration Timetable
A fixed iteration timetable will be defined and followed from day one of the next engagement. Each iteration has a hard exit date, a goal statement, and a scope ceiling. Work that does not fit the current iteration moves to the next backlog, not to an extended sprint. This disciplines scope, improves commit frequency, and ensures deliverables are staged progressively rather than front-loaded at the end.

### RITA — Real Intelligence Threat Analytics
RITA (Real Intelligence Threat Analytics) was in scope as a C2 detection tool but could not be integrated due to time constraints. RITA excels at detecting long-connection beaconing patterns in Zeek/Bro logs — exactly the Cobalt Strike ~202s beacon interval confirmed in H1. In a future engagement, RITA would run alongside tshark to provide a second independent confirmation of C2 beaconing, and its scoring output (`rita show-beacons`) would be a high-value addition to A.4 IOC documentation.

### OWASP ZAP — Automated Web Scanner
OWASP ZAP was available and known but not used due to time constraints in Iteration 3. ZAP's active scan against DVWA and Juice Shop would complement the manual Burp Suite testing by surfacing findings that manual enumeration might miss — particularly in the A07 (authentication) and A04 (insecure design) categories. The ZAP HTML report would also serve as an independent cross-check on the Semgrep CE static findings. Next time, ZAP is run as a first automated pass before manual testing begins, not as an optional addition.

### Cloud and Data Center Security Layer
The Meridian FinServe architecture includes a public cloud footprint and co-located data centers — both in scope for the threat model but not deeply assessed in this engagement. Future iterations should include:
- **AWS/Cloud misconfiguration review** — S3 bucket exposure, IAM role overpermissioning, IMDS v1 access (`169.254.169.254` endpoint — referenced in WS-C findings)
- **Data center network segmentation** — east-west controls between co-located DC and cloud workloads
- **Cloud-native logging** — CloudTrail / VPC Flow Logs as a complement to PCAP analysis for detecting lateral movement and data exfiltration in cloud segments
- **CSPM tooling** — Cloud Security Posture Management to baseline misconfigurations before and after remediation, analogous to what Semgrep CE does at the code layer

This would extend the Defense-in-Depth proposal's coverage from the application and network layers into the infrastructure layer where NBFC-scale data actually resides.

### Peer Review Gate on Machine-Readable Artifacts
IOC tables (CSV), SAST results (JSON), and hypothesis verdicts should require one team member to run a verification step before merge — specifically, confirming that every IOC row has a passing tshark filter returning at least one frame from the source PCAP. This is a lightweight gate that catches the highest-consequence errors in the least time.

---

## 05. Technical Achievements

| Achievement | Detail |
|-------------|--------|
| C2 beaconing confirmed | 28 TLS sessions · ~202s intervals · JA3 `6734f37431670b3ab4292b8f60f29984` |
| Lateral movement confirmed | Frame 10799 · `svcctl` CreateService + StartService · DC infected T+299s later |
| Data exfiltration confirmed | 4 POST flows · machine-name-embedded URIs · `/rob87/` and `/tot108/` patterns |
| SQL Injection full chain | Error-based → column enumeration → UNION extraction → full credential dump (5 accounts) |
| XSS — 3 security levels | Low (no filter) · Medium (`str_replace` bypass) · High (`preg_replace` bypass) — all patched |
| IDOR confirmed | `/api/statements/{id}` · 1,80,000 borrower records enumerable · no rate limit |
| Padding Oracle Attack | DVWA cryptography · A02 token forgery demonstrated |
| SAST before/after | 169 → 168 findings · A04 hardcoded JWT confirmed cleared (1 → 0) |
| Cross-surface attack chain | Frame 10799 `svcctl` → LSASS credential → portal auth bypass → IDOR enumeration |
| Defense-in-Depth | 7-layer proposal · Identity → Perimeter → Segmentation → Application → Data → Observability → Response |

---

## 06. Tools & Methodology Assessment

| Tool | Used For | Assessment |
|------|----------|------------|
| **tshark** | PCAP filtering, IOC extraction, hypothesis testing | ✅ Command-line filters are the reproducible audit trail |
| **Wireshark** | Initial triage, statistics, conversation analysis | ✅ Best for visual pattern recognition |
| **Semgrep CE** | SAST baseline before/after · OWASP top-ten ruleset | ✅ Machine-readable remediation evidence |
| **Burp Suite Community** | Request interception, payload testing, IDOR enumeration | ✅ Sufficient for all WS-B findings |
| **Docker** | Lab environment isolation | ✅ Zero environment conflicts |
| **Mermaid** | Architecture diagrams, attack chains | ✅ Version-controllable, renders in GitHub |
| **LLM (Claude)** | Payload generation, protocol explanation, prose drafting | ✅ With verification — valuable force multiplier |
| **RITA** | C2 beacon detection via Zeek logs | 🔜 Known · not used due to time — planned for next engagement |
| **OWASP ZAP** | Automated web vulnerability scanning | 🔜 Known · not used due to time — planned for next engagement |
| **Cloud CSPM** | Cloud misconfiguration baseline | 🔜 Planned — cloud layer assessment in scope for next iteration |

---

## 07. Engagement Success Criteria — Final Check

> *The engagement is successful when an independent reader, given only the GitHub repository, can reconstruct what was found, why it is believed, how it would be fixed, and what trade-offs were considered.*

| Criterion | Status |
|-----------|--------|
| What was found | ✅ All findings documented with request/response evidence |
| Why it is believed | ✅ tshark frame citations · Burp evidence · SAST JSON diffs |
| How it would be fixed | ✅ 5 code patches · 1 config patch · 1 compensating control |
| What trade-offs were considered | ✅ Q4 reflection · Defense-in-Depth effort/cost annotations |
| Environment reproducible <15 min | ✅ docker-compose committed · seed state documented |
| No real PII in any artifact | ✅ All machine names and credentials from public PCAP corpora |

---

## 08. Three Takeaways

**The finding that mattered most:**
The `svcctl` call at frame 10799 — because until that frame the intrusion looked like a single contained workstation infection, and that one DCE/RPC exchange changed the scope from one host to an entire domain in under 5 microseconds.

**The tool to add next time:**
RITA for automated beacon detection and OWASP ZAP for automated web scanning — both tools were known and available but not used due to time constraints; both would directly strengthen the evidence base in WS-A and WS-B respectively.

**The control with the highest engagement leverage:**
MFA on portal accounts — the single gap at the exact surface boundary between WS-A and WS-B where a network-layer credential becomes a web portal session. Closing it breaks the cross-surface attack chain regardless of how sophisticated the network intrusion was.

---

*Project KaVacH · Sprint 2–3 Combined Engagement*
*Futurense AI Clinic × IIT Roorkee · June 2026*
