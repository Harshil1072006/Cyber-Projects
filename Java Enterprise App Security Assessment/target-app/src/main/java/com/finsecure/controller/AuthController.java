package com.finsecure.controller;

import com.finsecure.model.User;
import com.finsecure.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

/**
 * Authentication Controller — Login & Register
 *
 * Issues JWTs signed with the hardcoded secret "secret123".
 * The alg:none bypass in JwtFilter means the signature doesn't matter.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    // VULN: Same hardcoded secret as JwtFilter — CWE-798
    private static final String SECRET_KEY = "secret123";

    @Autowired
    private UserRepository userRepository;

    // ─────────────────────────────────────────────────────────
    // POST /api/auth/register
    // ─────────────────────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody User user) {
        // VULN: Password stored in plaintext — no hashing
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "User registered: " + user.getUsername()));
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/auth/login
    // ─────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> creds) {
        String username = creds.get("username");
        String password = creds.get("password");

        Optional<User> optUser = userRepository.findByUsername(username);

        if (optUser.isEmpty() || !optUser.get().getPassword().equals(password)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        User user = optUser.get();

        // Issue JWT signed with hardcoded secret
        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .claim("role", user.getRole())
                .claim("userId", user.getId())
                .setIssuedAt(new Date())
                // VULN: No expiration set — token valid forever
                // Secure fix: .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();

        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.getUsername(),
                "role", user.getRole()
        ));
    }
}
