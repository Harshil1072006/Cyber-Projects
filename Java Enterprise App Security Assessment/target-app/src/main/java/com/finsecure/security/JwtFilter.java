package com.finsecure.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * JWT Authentication Filter
 *
 * ============================================================
 * INTENTIONAL VULNERABILITIES (for security assessment demo):
 * ============================================================
 *
 * VULN-1: JWT Algorithm Confusion (alg: none bypass)
 *   - This filter parses JWT tokens using Jwts.parser() WITHOUT
 *     calling .setSigningKey(). This means any JWT with alg:none
 *     and no signature passes validation.
 *   - Attacker can forge any token by base64-encoding a header
 *     with {"alg":"none"} and any claims they want.
 *   - CWE-347: Improper Verification of Cryptographic Signature
 *   - CVSSv3: 9.1 Critical
 *
 * VULN-2: Hardcoded JWT Secret
 *   - The secret key SECRET_KEY = "secret123" is hardcoded in source.
 *   - An attacker who finds this (via SAST, leaked repo, jar decompile)
 *     can forge valid signed tokens for any user.
 *   - CWE-798: Use of Hard-coded Credentials
 *   - CVSSv3: 7.5 High
 *
 * VULN-3: No Token Expiry Validation
 *   - Expired tokens are accepted indefinitely. A stolen token
 *     never becomes invalid.
 *   - CWE-613: Insufficient Session Expiration
 */
public class JwtFilter extends OncePerRequestFilter {

    // VULN-2: Hardcoded secret — should come from environment variable
    private static final String SECRET_KEY = "secret123";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                // VULN-1: Parsing WITHOUT setSigningKey() — accepts alg:none tokens
                // Secure fix: Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
                Claims claims = Jwts.parser()
                        // .setSigningKey(SECRET_KEY)  ← INTENTIONALLY COMMENTED OUT
                        .parseClaimsJwt(token)          // ← accepts unsigned tokens
                        .getBody();

                // VULN-3: No expiry check — claims.getExpiration() is never validated
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                if (username != null) {
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    List.of(new SimpleGrantedAuthority("ROLE_" + (role != null ? role : "USER")))
                            );
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            } catch (Exception e) {
                // VULN: Swallows all JWT errors silently — unauthenticated requests
                // might still proceed if a later filter doesn't enforce auth
                response.setHeader("X-JWT-Error", e.getMessage()); // leaks internal error info
            }
        }

        filterChain.doFilter(request, response);
    }
}
