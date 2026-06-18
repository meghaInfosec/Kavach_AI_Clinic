# Project KaVacH — Individual Reflection
## Question 8

---

> **Q8:** Look at your repository's commit history. Identify the commit you are most proud of and the commit you would, on reflection, redo. Explain both in one sentence each.

---

## The Commit I Am Most Proud Of

**Commit: `A.3 — Hypothesis-Driven Deep Dive (Hypotheses.md)`**

The hypothesis-driven deep dive is the commit I am most proud of because it is the only deliverable in the entire repository where I began with genuine uncertainty — three competing explanations for the same traffic — and resolved each one to a high-confidence verdict entirely through primary PCAP evidence: exact tshark commands, specific frame numbers, and inter-arrival timing calculations that left no room for interpretation.

The result — three confirmed hypotheses with reproducible tshark filters, precise frame citations (frame 10799 for lateral movement, frame 2910 for first exfiltration, frame 791 for beacon onset), and a timeline accurate to the second — is the analytical backbone that every downstream deliverable in Workstream A depends on. The threat model cites it. The attack chains cite it. The defense-in-depth proposal's motivation tables cite it. Without that commit done rigorously, the synthesis layer of the project would have been built on unverified claims rather than ground truth.

What makes it the commit I return to is not the quantity of evidence — it is the discipline of the structure: for every hypothesis, a falsification test was written before the verdict was given. The lateral movement hypothesis, for instance, could have been called confirmed after seeing high SMB volume from the workstation to the DC. Instead, the falsification test required finding `svcctl` calls specifically — because high SMB volume is consistent with normal domain authentication, but `svcctl` is not. That distinction is the difference between a correlation and a finding.

---

## The Commit I Would Redo

**Commit: `A.4 — Indicator Extraction (iocs.csv — initial version)`**

The initial `iocs.csv` commit is the one I would redo, because it contained a fabricated URI pattern — `/collect/.*` listed as a High-confidence Data Exfiltration indicator — that returned zero matching frames when run against the actual PCAP, meaning the IOC was never verified against the source file before being committed to the repository.

The error was compounded: the same commit contained incorrect frame ranges for three other entries (the `37.228.70.134` beacon was listed as frames `791–26477` when the correct range is `791–26451`; the `192.236.155.230` session was listed as frames `1200–24500` when tshark confirms `3049–19069`; the lateral movement entry cited frames `4500–8000` when the `svcctl` exchange occurs from frame `10799` onward), and the Cobalt Strike User-Agent was recorded as a `Windows NT 10.0` string — a UA present in the 2018 PCAP the team was concurrently analysing, not the 2021 Trickbot capture. The root cause, documented in the project retrospective under STOP, was running concurrent analysis on two different PCAP captures simultaneously without a single-source-of-truth agreement in place; the IOC table absorbed values from both captures without any per-row tshark verification before commit.

The corrected version — with `[PCAP-CORRECTED]` annotations on eight entries, the `/collect/.*` row explicitly marked `INVALID` and `NOT FOUND IN PCAP`, and the genuine Trickbot URIs (`/rob87/DESKTOP-OG16DGY_.../90` and `/tot108/VICTORYPUNK-DC_.../90`) added as replacements — recovered the accuracy, but the initial commit had already been pushed. In a real engagement, a fabricated IOC in a delivered indicator table is not a formatting error — it is actionable intelligence that a defender may act on, block, or file a report around. The consequence of an IOC that matches zero frames in the source PCAP being distributed to a SOC is a wasted detection rule and eroded confidence in the entire table. The redo would be to require a passing tshark filter run — confirming at least one matching frame in the PCAP — as a gate condition for every row before any IOC is committed.

---

*Reflection submitted as part of Project KaVacH — IIT Roorkee × Futurense Technologies*  
*Megha Sharma | Network Forensics Lead & Web App Co-Lead*
