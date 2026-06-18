# Project KaVacH — Individual Reflection
## Question 4

---

> **Q4:** For the same vulnerability, describe the remediation you wrote at the code level. Why did you choose that fix over at least one alternative the team considered. What does the alternative cost or break that yours does not.

---

## Vulnerability: SQL Injection (OWASP A03:2021)
**Target:** DVWA `http://localhost:8082/vulnerabilities/sqli/`  
**Backend:** MariaDB `10.1.26-MariaDB-0+deb9u1`  
**Parameter:** `id` (GET)

---

## The Vulnerable Code (Before Fix)

The original DVWA low-security PHP code directly interpolated the user-supplied `id` parameter into the SQL query string:

```php
$id = $_GET['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

This is a textbook unsanitized string interpolation — the value of `$id` becomes part of the SQL command itself with zero separation between data and instruction. Any input containing a single quote immediately escapes the string literal and begins injecting arbitrary SQL logic.

---

## The Fix I Wrote: Parameterized Query (Prepared Statement)

```php
$id = $_GET['id'];

$stmt = $GLOBALS["___mysqli_ston"]->prepare(
    "SELECT first_name, last_name FROM users WHERE user_id = ?"
);
$stmt->bind_param("s", $id);
$stmt->execute();
$result = $stmt->get_result();
```

### Why This Works

A prepared statement separates the SQL structure from the data in two distinct phases:

1. **Prepare phase** — the database engine compiles the query template `WHERE user_id = ?` into an execution plan. The `?` is a placeholder, not a string slot. The query structure is now fixed and cannot be altered.
2. **Bind phase** — `$id` (whatever value the user provides) is passed to the database as a raw data value, not as text to be parsed. The engine treats it entirely as a literal string to match against, never as SQL syntax.

This means our entire Phase 1–5 payload progression from Q3 becomes structurally impossible:
- `'` — the single quote is passed as a character to match, not as a string delimiter
- `1' ORDER BY 3-- '` — the `ORDER BY` is passed as literal data, not a SQL clause
- `2' union select user, password FROM users -- '` — the `union` keyword is passed as a data string, not a query combinator

The database never sees these as SQL. It only ever sees them as the value of `user_id` being compared, so they simply return no results instead of executing.

---

## The Alternative the Team Considered: Input Validation / Blocklist Filtering

The other approach our team discussed was input sanitization — inspecting and rejecting or escaping dangerous input before it reached the query.

### How it would look in code:

```php
// Approach A: Whitelist — only allow digits
$id = $_GET['id'];
if (!ctype_digit($id)) {
    die("Invalid input.");
}
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";

// Approach B: Escape special characters
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $_GET['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

### Why the Team Initially Liked It

- It felt intuitive — "if we block the bad characters, nothing bad can enter"
- `mysqli_real_escape_string` is a built-in PHP function and looks authoritative
- The whitelist approach (digits only) seemed clean for a numeric `id` field

---

## Why I Chose Parameterized Queries Over Input Validation

### 1. Input validation is context-dependent; prepared statements are not

`mysqli_real_escape_string` escapes characters that are dangerous in a **string context** — it adds backslashes before `'`, `"`, `\`, and so on. But SQL injection does not always occur inside a string context. Consider:

```php
// Integer context — no quotes around $id
$query = "SELECT * FROM users WHERE user_id = $id";
```

Here `mysqli_real_escape_string` does nothing — there are no quotes to escape. The payload `1 OR 1=1` would work perfectly because there is no string delimiter to break in the first place. The fix is context-specific; it works for the exact case it was written for and silently fails the moment the query structure changes slightly.

A prepared statement does not care about context. The `?` placeholder is always data, regardless of whether the query surrounds it with quotes or not.

### 2. The blocklist is a guessing game; the whitelist breaks legitimate use

A blocklist approach (block `'`, `--`, `UNION`, etc.) requires us to enumerate every possible dangerous token — an arms race we cannot win. Attackers use encoding tricks (`%27` for `'`, double encoding, Unicode variants) to bypass keyword filters. The OWASP SQLi cheat sheet documents dozens of such bypasses.

The whitelist (digits only) avoids that problem for this specific field, but it is not a general solution:
- It breaks immediately for any non-numeric field (names, search terms, email addresses)
- It couples our security assumption to the data type — if the schema ever changes or a second parameter is added, the assumption silently no longer holds
- It still leaves the underlying query vulnerable; we are only masking the attack surface for one input

### 3. Escaping depends on correct implementation at every call site

`mysqli_real_escape_string` must be called on every user input, every time, at every point in the codebase. Miss one — even once — and the entire defense collapses at that call site. Prepared statements, by contrast, make it architecturally impossible to mix data and instruction: the query template is written once with placeholders, and data is always bound separately. There is no "forgot to sanitize" failure mode.

---

## What the Alternative Costs or Breaks That My Fix Does Not

| Dimension | Parameterized Query | Input Validation / Escaping |
|:---|:---|:---|
| Protection scope | All SQL contexts (string, integer, LIKE, etc.) | Only the specific context it was written for |
| Bypass resistance | Structurally impossible to bypass | Bypassable via encoding, edge cases, new SQL dialects |
| Developer error surface | One pattern, enforced by API contract | Must be applied correctly at every call site |
| Application logic breakage | None — query behavior unchanged | Whitelist breaks non-numeric fields; blocklist may reject valid inputs containing flagged keywords (e.g. a user named `null` or a city named `Union`) |
| Performance | Negligible overhead; most drivers cache prepared statements | Marginally faster per call but offers no structural guarantee |
| Maintenance cost | Low — placeholder syntax is stable | High — blocklist must be updated as new bypass techniques emerge |

### The Single Clearest Reason

Input validation treats SQL injection as a character problem — "remove the bad characters."  
Prepared statements treat it as an architectural problem — "never let user data become SQL syntax."

The first approach fights the symptom. The second eliminates the condition that makes the symptom possible.

---

## One Remaining Consideration: Defence in Depth

Choosing parameterized queries does not mean input validation has no role. Our team's final recommendation was to layer both:

- **Prepared statements** as the primary, structural defence — this eliminates injection
- **Type validation** (`ctype_digit` for numeric IDs, length checks, format checks) as a secondary layer — not for security, but for data integrity and early error surfacing

The key distinction is that the second layer is there to enforce application logic, not to compensate for an insecure query. Defence in depth means having multiple independent layers — not having one layer so brittle that you need another to cover its gaps.

---

*Reflection submitted as part of Project KaVacH — IIT Roorkee × Futurense Technologies*  
*Megha Sharma | Network Forensics Lead & Web App Co-Lead*
