# DVWA — Stored XSS (Low Level)

## Overview

| | |
|---|---|
| **Vulnerability** | Stored Cross-Site Scripting (XSS) |
| **Target application** | DVWA (Damn Vulnerable Web Application) |
| **Module** | XSS (Stored) — Guestbook |
| **Security level** | Low |
| **URL** | `http://localhost:8082/vulnerabilities/xss_s/` |
| **Tools used** | Firefox (no proxy/interception required) |

Stored XSS occurs when user-supplied input is saved on the server (e.g. in a database) and later rendered back to *any* visitor without proper sanitization. Unlike reflected XSS, no social engineering (tricking a victim into clicking a crafted link) is required — the payload fires automatically for every user who views the affected page.

At **Low security level**, DVWA applies no meaningful sanitization to either the `Name` or `Message` fields, making this the simplest possible demonstration of the vulnerability — no filter bypass or proxy tooling needed.

---

## 1. Source code analysis

**File:** `xss_s/source/low.php`

**Screenshot — DVWA "View Source" page for XSS (Stored), low level:**

![DVWA view source page showing low.php source code](Evidences/01b-low-view-source.png)
*(placeholder — attach screenshot of the View Source popup here)*

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $message );
    $message = strip_tags( $message, '<b>' );

    // Sanitize name input
    $name = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $name );

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query( $GLOBALS["___mysqli_ston"], $query );
}
?>
```

### Key observation — minimal filtering on both fields

| Field | Filtering applied | Effective against XSS? |
|---|---|---|
| **Message** | `mysqli_real_escape_string()` (SQL injection only) + `strip_tags($message, '<b>')` (allows `<b>` through, strips other tags) | Partial — most tags removed, but `<b>` itself remains and any `<script>` variant not caught by `strip_tags` slips through in practice |
| **Name** | `mysqli_real_escape_string()` only (SQL injection only) | None — zero HTML/JS filtering |

`mysqli_real_escape_string()` protects against **SQL injection** (it escapes quote characters for safe database insertion) — it does **nothing** to prevent HTML or JavaScript from being stored and rendered. The `Name` field has no XSS-specific filtering at all, and `Message` only strips most tags via `strip_tags()`, which itself is a weak, non-context-aware defense (unlike proper output encoding).

---

## 2. Attack plan

1. No bypass technique required — low level has no meaningful blacklist to defeat.
2. Submit a standard `<script>` payload directly through the browser form.
3. Confirm the payload executes immediately on submission.
4. Reload the page to confirm persistence — the defining trait of stored XSS.

---

## 3. Executing the attack

**Step 1 — Open the empty guestbook form:**

![Stored XSS guestbook form, low level, empty](Evidences/00-low-level-guestbook-form.png)

**Step 2 — Submit the payload directly (no proxy tooling needed):**

| Field | Value |
|---|---|
| Name | `test` |
| Message | `<script>alert('Stored XSS')</script>` |

Click **Sign Guestbook**.

**Step 3 — Alert fires immediately on submission**, since the page reloads and displays the guestbook entries — including the newly stored one — right after posting.

**Step 4 — Confirm persistence**

Refresh the page (F5), or navigate away and return. The alert fires again on every load, confirming the payload is stored in the database, not just reflected in a single response.

![Stored XSS alert firing repeatedly on page reload, low level](Evidences/00b-low-level-popup-success.png)

---

## 4. Verification — persistence confirmed

Unlike reflected XSS (which requires a victim to click a specifically crafted URL), this payload now lives permanently in the `guestbook` table. **Every visitor** who loads `http://localhost:8082/vulnerabilities/xss_s/` will trigger the alert automatically, with no further interaction, until an administrator manually removes the entry from the database.

---

## 5. Summary of findings

| Check | Result |
|---|---|
| Any HTML/JS-specific filtering on Name field? | ❌ No — only SQL-escaping applied |
| Any HTML/JS-specific filtering on Message field? | ⚠️ Partial — `strip_tags()` allows `<b>` through and is bypassable for other payloads (e.g. attribute-based vectors like `<img onerror=...>` that don't rely on stripped tags) |
| Output encoded before rendering (`htmlspecialchars()` or equivalent)? | ❌ No — payload stored and rendered completely raw |
| Payload persists across page reloads? | ✅ Yes — confirmed stored in database |
| Filter bypass technique required? | ❌ No — plain `<script>` payload works unmodified |

## 6. Root cause

No output encoding is applied anywhere in this code path, and `Name` has no XSS-aware input handling whatsoever. `mysqli_real_escape_string()` is a **SQL-injection defense**, frequently and mistakenly assumed to also cover XSS — it does not, since it only escapes characters meaningful to the SQL parser (like quotes), not characters meaningful to the HTML parser (like `<` and `>`).

## 7. Remediation

- Apply context-aware output encoding (`htmlspecialchars()` or equivalent) to **both** fields before rendering them back into HTML.
- Do not rely on `strip_tags()` alone — it is a blacklist-style defense with known bypasses (attribute-based payloads, malformed tags, etc.).
- Do not conflate SQL-injection defenses (`mysqli_real_escape_string`) with XSS defenses — they protect against entirely different injection contexts and must both be applied independently, at the correct output boundary (database query vs. HTML response).

---

*Documented as part of DVWA practice — CloudGuardian / KAVACH capstone security learning track.*
