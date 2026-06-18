# Project KaVacH — Individual Reflection
## Question 7

---

> **Q7:** What is one decision in the defense-in-depth proposal that you would lose sleep over if you were the CISO who had to fund it. What is the trade-off, and why did the team still recommend it.

---

## Prefatory Note on Scope

The Defense-in-Depth proposal (KAVACH-WC-DiD-001) contains twenty-eight discrete controls spanning seven layers. Several are immediately uncomfortable from a funding perspective — PAM for Active Directory (ID-05) requires months of AD restructure and a culture shift that most IT organisations actively resist; east-west microsegmentation (SEG-01) requires full traffic flow mapping and will cause service disruptions before it improves anything. Both deserve serious scrutiny.

However, the control that presents the deepest and most structurally irreversible trade-off — the one that, as CISO, I would return to at 2 a.m. not because it is optional, but precisely because it is not — is **DAT-02: Field-Level Encryption of PII at Rest**.

This reflection sets out exactly what that decision entails, why the trade-offs are materially more severe than the proposal's summary table suggests, and why the evidence from both workstreams nevertheless made the recommendation unavoidable.

---

## The Control: DAT-02 — Field-Level PII Encryption at Rest

### What the Proposal Says

> *"Encrypt high-sensitivity fields (Aadhaar, PAN, mobile number, account number) at the application layer before writing to the database. Encryption keys stored in vault (ID-04), not on the DB server. A DB dump without the key yields ciphertext only."*
>
> **Effort:** L — schema change + data migration + key management infrastructure  
> **Trade-off:** Significant performance overhead on high-cardinality search queries against encrypted fields. Some analytics pipelines that query PII directly will break and require redesign.

The proposal assigns this control an Effort rating of **L (months)** and lists two trade-offs in a single sentence. What follows is what that sentence is actually describing.

---

## The Full Weight of the Trade-Off

### 1. The Vault Dependency Is a New Category-One Availability Risk

DAT-02 is not a standalone control. It depends structurally on **ID-04** — the secrets vault that stores the encryption master keys. The proposal states this explicitly: keys are held in HashiCorp Vault or AWS Secrets Manager, not on the database server.

This creates a dependency chain that did not previously exist:

```
Vault unavailable
  → Application cannot retrieve field decryption key at runtime
    → Application cannot decrypt PII fields on read
      → Every customer-facing query that touches Aadhaar, PAN, or account number fails
        → Customer portal goes dark
          → Partner portal goes dark
            → Loan servicing stops
              → EMI processing stops
```

Meridian FinServe is a regulated NBFC. Under the Reserve Bank of India's IT Framework for NBFCs, availability of the loan servicing system is not discretionary. A CISO who recommends DAT-02 is simultaneously recommending the introduction of a new single point of failure whose unavailability produces a system-wide outage. The proposal does note this risk for ID-04 in isolation ("if vault is unavailable, applications cannot start"), but it does not follow that thread to its operational conclusion at the DAT-02 level: once PII is encrypted, the vault is no longer an infrastructure concern — it is a business continuity concern.

The vault must therefore be deployed as a high-availability cluster, with documented recovery procedures, tested failover, and an on-call rotation for vault incidents — before DAT-02 goes live. None of that is inside the effort estimate for DAT-02 itself.

### 2. The Schema Migration Runs Against a Live Lending Database

Encrypting existing PII fields is not a configuration change. It is a database schema migration against a production system that holds 1,80,000 active borrower records, active loan accounts, and active EMI schedules. The migration must:

- Add new ciphertext columns alongside each plaintext field
- Encrypt every existing value at the application layer (not in-database)
- Verify integrity of each encrypted row before dropping the plaintext column
- Handle in-flight writes during the migration window — records written during migration are in an inconsistent state unless the application is taken offline or a write lock is held

For a mid-sized NBFC with continuous transaction processing, a write lock or offline window is not a routine maintenance decision. It requires RBI advance notification if it affects customer-facing availability, coordination with payment processors, and a rollback procedure that must itself be tested against production data volumes. The migration cannot be rehearsed in isolation on a development database because the production load profile is the variable that determines whether the migration completes within the maintenance window.

If the migration fails partway through — if a row fails to encrypt correctly, or if the application fails to start against the new schema — the rollback path is to restore from backup. That means data loss covering the period since the last backup, which in a lending system means lost payment records, lost EMI updates, and lost loan state changes. The CISO funding this control is also funding the possibility of that rollback.

### 3. Encrypted Fields Break Analytical Queries That the Business Depends On

The proposal notes that "some analytics pipelines that query PII directly will break and require redesign." The word *some* understates the scope.

Meridian FinServe's lending operations depend on queries that filter, sort, aggregate, and join against precisely the fields that DAT-02 proposes to encrypt. Credit decisioning may filter by PAN to retrieve a borrower's full credit history. Reconciliation processes join on account numbers. KYC verification compares Aadhaar hashes. Fraud detection systems scan account number patterns across the borrower population.

None of these queries work against encrypted ciphertext in the conventional sense. The standard application-layer encryption model (encrypt on write, decrypt on read by fetching the individual row) does not support `WHERE pan_number = ?` or `ORDER BY account_id` against encrypted fields without either:

- Decrypting the entire column in memory at query time — which destroys the performance characteristic of indexed lookup and scales linearly with row count rather than logarithmically, and which is operationally equivalent to a full table scan on a 1,80,000-row borrower table on every filtered query, or
- Adopting deterministic encryption (encrypt the same value to the same ciphertext, allowing equality comparison) — which reintroduces a class of frequency analysis attack that partially undermines the security guarantee DAT-02 is meant to provide, or
- Re-architecting the affected pipelines to use tokenised references via DAT-03, which is a separate control with its own effort and its own breakage surface.

The analytics and risk teams who currently write direct SQL queries against the core database will lose that capability. Those are not optional pipelines — they are the loan origination, underwriting, and collections infrastructure for an NBFC with 1,80,000 active borrowers. Redesigning them is not a side project. It is the primary project, running in parallel with a schema migration, against a live system, with a regulatory obligation to maintain service continuity.

### 4. The Cascading Sequence Required Is Significantly Longer Than the Effort Rating Conveys

DAT-02 cannot be responsibly deployed until:

1. **ID-04** (secrets vault) is deployed, tested, and operating in high-availability configuration
2. The vault's availability SLA has been established and contractually secured (if cloud-managed) or operationally validated (if self-hosted)
3. A vault incident runbook exists and has been tested
4. All affected application services have been refactored to fetch keys at runtime rather than reading from config files
5. The analytics pipeline inventory has been completed, identifying every query that touches Aadhaar, PAN, account number, or mobile number fields
6. Replacement queries have been written, tested, and signed off by the business teams who depend on them
7. A migration plan with tested rollback procedure has been rehearsed against a production-scale data clone
8. A maintenance window has been agreed with RBI-required advance notice if applicable
9. Post-migration monitoring is in place to detect decryption failures before they surface as customer complaints

None of items 1 through 9 appear in DAT-02's effort estimate. They are prerequisites, and several of them are themselves months-long efforts.

---

## Why the Team Still Recommended It

### The Finding That Made It Non-Negotiable

During Workstream B, the IDOR vulnerability on the `/api/statements/{account_id}` endpoint was confirmed to allow sequential enumeration of all 1,80,000 borrower statement records without rate limiting or per-object authorisation checks. The attack is a loop:

```
GET /api/statements/1       → full borrower record returned
GET /api/statements/2       → full borrower record returned
...
GET /api/statements/180000  → full borrower record returned
```

The records returned include Aadhaar-linked identities, PAN numbers, mobile numbers, account numbers, loan amounts, and EMI payment history. The IDOR itself has been remediated under APP-02. But the IDOR is not the only path to the same data.

Workstream A confirms an active Cobalt Strike implant on the domain controller at the time of the engagement. Chain 2 in the Joint Threat Model (KAVACH-WC-TM-001) shows SQL injection on the portal login endpoint progressing through DB credential extraction to direct TCP access on port 1433, to `xp_cmdshell` OS-level execution. Chain 3 shows Pass-the-Hash lateral movement to the application server, reading the DB credential from `/var/www/config/web.config` in plaintext, and connecting directly to the core database.

In both chains, the attacker reaches the core database and performs a bulk dump. The records exfiltrated are identical to those accessible via the IDOR. The question DAT-02 answers is: **what does the attacker have after that dump?**

Without field-level encryption, the answer is: 1,80,000 complete borrower records in cleartext — Aadhaar, PAN, account numbers, loan history. Immediately actionable for financial fraud, identity theft, and targeted phishing at scale.

With field-level encryption, the answer is: ciphertext that is computationally unusable without the Vault master key, which is not stored on the database server and is not accessible via any of the attack paths demonstrated in either workstream.

The outer layers — APP-01 (parameterised queries), APP-02 (object-level authorisation), SEG-01 (microsegmentation), PR-03 (egress filtering) — reduce the probability of the attacker reaching the database. DAT-02 reduces the impact when, despite those controls, an attacker reaches it anyway. In a seven-layer defence-in-depth model, impact reduction at the Data layer is not a preference. It is the structural guarantee that the outer layers are permitted to be imperfect.

### The Regulatory Obligation Is Not Discretionary

Meridian FinServe, as an NBFC regulated by the Reserve Bank of India, operates under the RBI IT Framework for NBFCs and the Master Direction on IT Governance. The framework requires that customer data, particularly data in the category of sensitive personal information, be protected by controls proportionate to its classification. Aadhaar numbers and PAN numbers are the most sensitive identifiers in the Indian financial system — their compromise in a data breach triggers mandatory breach notification obligations.

The Digital Personal Data Protection Act (DPDP Act, 2023) additionally places obligations on data fiduciaries — which Meridian is, by virtue of processing personal data of its 1,80,000 borrowers — to implement appropriate technical and organisational measures to protect personal data. The Act empowers the Data Protection Board of India to impose penalties of up to INR 250 crore for significant breaches involving inadequate technical safeguards.

A CISO who declines to recommend field-level encryption of Aadhaar and PAN data, in the context of a confirmed DB-dump-capable attack chain, is making a documented decision to accept the regulatory exposure that follows from a breach. That decision is defensible in a risk-acceptance framework, but it must be made explicitly, with board-level sign-off, and with the penalty quantum acknowledged. The team's assessment is that the cost of implementing DAT-02 correctly — including all prerequisites — is materially lower than the cost of a confirmed breach of 1,80,000 Aadhaar-linked records, even before accounting for reputational and operational consequences.

### Defence in Depth Requires That the Data Layer Not Be an Exception

The proposal's concept note states: *"Seven layers each at 80% strength is more secure than one layer at 99%."* DAT-02 is the Data layer's contribution to that model. If the Data layer is excluded from the model — if the implicit assumption is that the outer six layers will always hold — then the model provides seven layers of deterrence up to the database and zero layers of protection beyond it.

The WS-A PCAP documents an attacker who was inside the network for 72 hours before detection, with active Cobalt Strike implants on both a workstation and the domain controller, exfiltrating data through channels that went undetected for the full capture window. A defence-in-depth model that assumes perimeter, segmentation, and application controls will always intercept the attacker before they reach the database is not a defence-in-depth model — it is a perimeter model with decorative inner layers.

DAT-02 is recommended because the evidence from both workstreams demonstrates that the outer layers were insufficient to prevent a sophisticated attacker from reaching the data tier, and because the regulatory and business consequence of a cleartext dump of 1,80,000 Aadhaar-linked records is severe enough to justify the operational disruption of implementing the control correctly.

---

## What the CISO Should Insist On Before Approving It

Approving DAT-02 does not mean approving an immediate schema migration. The CISO funding this control should require the following as preconditions, in sequence:

| Precondition | Why It Cannot Be Skipped |
|:---|:---|
| ID-04 deployed and HA-tested before DAT-02 begins | Vault unavailability post-encryption = total application outage |
| Full analytics pipeline inventory completed | No control over breakage scope without this inventory |
| Business sign-off on pipeline redesign timeline | Avoids mid-migration discovery that a critical report is broken |
| Migration rehearsed on production-scale data clone | Production load profile determines whether the window is feasible |
| Rollback procedure tested, not just written | A written rollback that has never been executed is not a rollback plan |
| Maintenance window agreed with RBI notification if required | Regulatory obligation, not optional |
| Post-migration decryption monitoring in place | Silent decryption failures surface as customer data corruption |

Funding DAT-02 without these preconditions in place is not funding a security control. It is funding the conditions for an operationally catastrophic migration that may ultimately produce an outage larger than the breach it was designed to prevent.

---

## Summary

DAT-02 is the control in this proposal that keeps the CISO awake — not because it is wrong, but because it is right in a way that is genuinely difficult to operationalise. It introduces a new availability risk (the vault) in order to eliminate a data exposure risk (cleartext PII). It requires a live schema migration against a regulated lending database. It breaks the analytical infrastructure that runs the business. And it must be sequenced behind a prerequisite (ID-04) that is itself a months-long effort.

The team recommended it because the alternative — leaving 1,80,000 Aadhaar-linked borrower records in cleartext against a confirmed active DB-dump-capable threat actor — is the one risk in the entire proposal that a regulated Indian NBFC cannot formally accept and document as tolerable. Every other control in the proposal reduces probability. This one reduces impact after every other control has failed. That is the control the data layer exists to provide.

---

*Reflection submitted as part of Project KaVacH — IIT Roorkee × Futurense Technologies*  
*Megha Sharma | Network Forensics Lead & Web App Co-Lead*
