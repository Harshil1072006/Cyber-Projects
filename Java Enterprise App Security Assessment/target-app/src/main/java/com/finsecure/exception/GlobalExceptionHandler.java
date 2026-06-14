package com.finsecure.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Global Exception Handler
 *
 * ============================================================
 * INTENTIONAL VULNERABILITY:
 * ============================================================
 *
 * VULN: Verbose Stack Trace Disclosure
 *   All unhandled exceptions return the full Java stack trace in the
 *   HTTP response body. This reveals:
 *     - Internal class names and package structure
 *     - File names and line numbers
 *     - Framework versions (Spring, Hibernate, etc.)
 *     - Database driver details
 *     - SQL query structure on DB errors
 *
 *   This massively aids attacker reconnaissance.
 *   CWE-209: Generation of Error Message Containing Sensitive Information
 *   CVSS: 5.3 Medium
 *
 *   Secure fix: Return only a generic error ID, log the full trace server-side.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAll(Exception ex) {
        // VULN: Captures and returns full stack trace to the client
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        String fullStackTrace = sw.toString();

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("error", ex.getClass().getName());         // e.g., "org.springframework.dao.DataAccessException"
        error.put("message", ex.getMessage());               // e.g., SQL syntax error with query
        error.put("stackTrace", fullStackTrace);             // VULN: Full 30-line stack trace in response
        error.put("cause", ex.getCause() != null            // Nested cause with DB driver details
                ? ex.getCause().getMessage() : null);

        // Also leak system properties for attacker fingerprinting
        error.put("javaVersion", System.getProperty("java.version"));
        error.put("springProfile", System.getProperty("spring.profiles.active", "default"));

        return ResponseEntity.status(500).body(error);
    }
}
