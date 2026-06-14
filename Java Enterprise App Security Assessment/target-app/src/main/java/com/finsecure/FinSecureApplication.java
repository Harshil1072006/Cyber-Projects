package com.finsecure;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * FinSecure API — Vulnerable Financial REST API
 *
 * WARNING: This application intentionally contains security vulnerabilities
 * for educational security assessment demonstration. DO NOT deploy in production.
 *
 * Planted vulnerabilities:
 *   - Second-Order SQL Injection (AccountController)
 *   - JWT alg:none bypass + hardcoded secret (JwtFilter)
 *   - Horizontal IDOR — no ownership check (AccountController)
 *   - Mass Assignment — admin flag injectable (AccountController)
 *   - SSRF via /api/fetch endpoint (UtilController)
 *   - Disabled CSRF + wildcard CORS (SecurityConfig)
 *   - Verbose stack traces (GlobalExceptionHandler)
 *   - Vulnerable dependencies in pom.xml (CVE-2019-14379, CVE-2022-22965, CVE-2015-6420)
 */
@SpringBootApplication
public class FinSecureApplication {

    public static void main(String[] args) {
        SpringApplication.run(FinSecureApplication.class, args);
        System.out.println("\n========================================");
        System.out.println("  FinSecure API started on port 8080");
        System.out.println("  Health: http://localhost:8080/api/health");
        System.out.println("  H2 Console: http://localhost:8080/h2-console");
        System.out.println("  WARNING: VULNERABLE APPLICATION");
        System.out.println("========================================\n");
    }
}
