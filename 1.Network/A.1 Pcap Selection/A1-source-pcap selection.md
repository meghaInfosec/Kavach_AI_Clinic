## A.1 Source PCAP Selection

**Capture:** `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap`
**Source:** Malware-Traffic-Analysis.net, published 26 May 2021 by Brad Duncan
**Hash:** *(to be filled in from the downloaded file — run `sha256sum` and paste the value here for the reproducibility record)*

### Why this capture qualifies

The brief requires the chosen capture to demonstrate at least one of: C2 beaconing, lateral movement, data exfiltration, scanning, or credential abuse. This capture demonstrates **three** of these, which is part of why it was selected — the deliverable is reasoning, and a richer capture gives more surface to reason about:

- **C2 beaconing** — a Cobalt Strike beacon to an external IP, with no SNI on any of its 28 TLS ClientHellos, checking in at ~202-second intervals for the entire 80-minute window.
- **Data exfiltration** — Trickbot's collection module POSTing harvested host data (machine name, fingerprint hash embedded in the URI path) to two redundant external servers, preceded by a public-IP-lookup reconnaissance step.
- **Lateral movement** — the infected workstation uses `svcctl` (the Windows Service Control Manager RPC interface, the PsExec mechanism) to compromise the domain controller roughly seven minutes later, which then begins its own exfiltration.

### Why this is a defensible analogue for Meridian FinServe

Trickbot-plus-Cobalt-Strike is one of the most consistently observed intrusion patterns in the BFSI sector: Trickbot began as a banking trojan and has repeatedly served as an initial-access and credential-harvesting foothold that pivots into Cobalt Strike for hands-on-keyboard follow-up, frequently ending in ransomware deployment against financial-services and healthcare targets. Meridian FinServe's profile — an Active Directory environment with branch offices, a domain controller, and a small set of internal segments handling SMB lending and merchant-payment data — maps closely onto the topology in this capture: a single workstation infection, lateral movement via SMB/`svcctl` to the DC, and exfiltration of host and credential data toward external infrastructure. The 72-hour anomalous east-west and outbound traffic window described in the Engagement Brief (Trigger A) is structurally consistent with exactly this kind of beaconing-plus-lateral-movement sequence, just compressed here into an 80-minute capture.

### Limitations and how they're addressed

This capture originates from a lab/testbed environment rather than a live financial institution, host and domain names (`victorypunk.com`, `DESKTOP-OG16DGY`) are clearly synthetic, and the capture window (80 minutes) is far shorter than Meridian's 72-hour incident window. These are treated as scaling differences, not structural ones: the writeup explicitly maps each observed technique (beaconing cadence, `svcctl`-based lateral movement, staged exfiltration) to how it would manifest over a longer real-world window, rather than treating the capture's timeline as literal. No re-anonymization is required, as the capture already uses non-sensitive placeholder identifiers consistent with the engagement's no-real-PII constraint.
