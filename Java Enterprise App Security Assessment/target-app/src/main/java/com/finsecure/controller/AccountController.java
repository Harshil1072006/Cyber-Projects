package com.finsecure.controller;

import com.finsecure.model.Account;
import com.finsecure.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Account REST Controller — Core Financial API Endpoints
 *
 * ============================================================
 * INTENTIONAL VULNERABILITIES (for security assessment demo):
 * ============================================================
 *
 * VULN-1: Second-Order SQL Injection
 *   Endpoint: POST /api/accounts/{id}/note  (stores user input)
 *             GET  /api/accounts/search      (retrieves + executes in raw SQL)
 *   The user's note is stored safely in the DB, but when the admin
 *   runs /api/accounts/search, it uses that stored note in a raw
 *   SQL string concatenation — classic second-order SQLi.
 *   CWE-89 | CVSS: 9.8 Critical
 *
 * VULN-2: Horizontal IDOR (Insecure Direct Object Reference)
 *   Endpoint: GET /api/accounts/{id}
 *   No check that the requesting user owns the account with {id}.
 *   Any authenticated user can access any account by incrementing the ID.
 *   CWE-639 | CVSS: 8.1 High
 *
 * VULN-3: Mass Assignment — Admin Flag Injectable
 *   Endpoint: POST /api/accounts
 *   The Account object is directly deserialized from the JSON body.
 *   isAdmin field is writable — any user can set themselves as admin.
 *   CWE-915 | CVSS: 8.8 High
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // ─────────────────────────────────────────────────────────
    // GET /api/accounts — List all accounts (no auth check on data scoping)
    // ─────────────────────────────────────────────────────────
    @GetMapping
    public ResponseEntity<List<Account>> getAllAccounts() {
        // Returns ALL accounts to any authenticated user — no ownership filter
        return ResponseEntity.ok(accountRepository.findAll());
    }

    // ─────────────────────────────────────────────────────────
    // GET /api/accounts/{id} — VULN-2: Horizontal IDOR
    // ─────────────────────────────────────────────────────────
    @GetMapping("/{id}")
    public ResponseEntity<?> getAccountById(@PathVariable Long id) {
        /*
         * VULN-2: There is NO check here that the JWT principal owns account {id}.
         * Secure fix would be:
         *   String currentUser = SecurityContextHolder.getContext()
         *       .getAuthentication().getName();
         *   if (!account.getOwnerEmail().equals(currentUser)) {
         *       return ResponseEntity.status(403).body("Forbidden");
         *   }
         */
        Optional<Account> account = accountRepository.findById(id);
        return account
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/accounts — VULN-3: Mass Assignment
    // ─────────────────────────────────────────────────────────
    @PostMapping
    public ResponseEntity<Account> createAccount(@RequestBody Account account) {
        /*
         * VULN-3: @RequestBody Account account deserializes the ENTIRE JSON body
         * into the Account object — including the 'isAdmin' field.
         *
         * Attack: POST /api/accounts {"ownerName":"Attacker","isAdmin":true}
         *
         * Secure fix: Use a dedicated AccountRequest DTO that only exposes
         * safe fields, then manually map to Account entity.
         */
        Account saved = accountRepository.save(account);
        return ResponseEntity.ok(saved);
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/accounts/{id}/note — VULN-1 (Part A): Store the note
    // ─────────────────────────────────────────────────────────
    @PostMapping("/{id}/note")
    public ResponseEntity<Map<String, String>> updateNote(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {

        String note = body.get("note");

        Optional<Account> optAccount = accountRepository.findById(id);
        if (optAccount.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Account account = optAccount.get();
        // The note is stored in the database — looks safe so far.
        // But this stored value will later be used unsafely in /search.
        account.setProfileNote(note);
        accountRepository.save(account);

        return ResponseEntity.ok(Map.of(
                "message", "Note updated successfully",
                "note", note
        ));
    }

    // ─────────────────────────────────────────────────────────
    // GET /api/accounts/search — VULN-1 (Part B): Second-Order SQLi trigger
    // ─────────────────────────────────────────────────────────
    @GetMapping("/search")
    public ResponseEntity<?> searchByNote(@RequestParam String note) {
        /*
         * VULN-1: Second-Order SQL Injection
         *
         * This query is constructed by concatenating the `note` parameter
         * directly into a SQL string. If the note was stored with a malicious
         * payload like: ' OR '1'='1' --
         * Then the query becomes: SELECT * FROM accounts WHERE profile_note = '' OR '1'='1' --'
         * which returns ALL accounts in the database.
         *
         * Why "second-order"? The payload is stored (step 1) and triggered
         * later by a different request (step 2). Many WAFs miss this pattern.
         *
         * Secure fix: Use parameterized queries — jdbcTemplate.query(sql, new Object[]{note}, ...)
         */
        String sql = "SELECT * FROM accounts WHERE profile_note = '" + note + "'";

        try {
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            // VULN: Returns raw SQL error message to the client — aids attacker enumeration
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // ─────────────────────────────────────────────────────────
    // GET /api/admin/accounts — Admin-only endpoint (bypassed via JWT alg:none)
    // ─────────────────────────────────────────────────────────
    @GetMapping("/admin/all")
    public ResponseEntity<?> adminGetAll() {
        // This should require ROLE_ADMIN, but the JwtFilter's alg:none bypass
        // lets any attacker forge a token with role: "ADMIN"
        return ResponseEntity.ok(Map.of(
                "message", "Admin access granted",
                "accounts", accountRepository.findAll(),
                "total", accountRepository.count()
        ));
    }
}
