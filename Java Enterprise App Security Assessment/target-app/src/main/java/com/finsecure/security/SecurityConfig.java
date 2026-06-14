package com.finsecure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Spring Security Configuration
 *
 * ============================================================
 * INTENTIONAL VULNERABILITIES (for security assessment demo):
 * ============================================================
 *
 * VULN-1: CSRF Protection Disabled
 *   - .csrf().disable() removes the CSRF token requirement on all
 *     state-changing requests (POST, PUT, DELETE).
 *   - An attacker can create a malicious page that makes cross-origin
 *     requests to authenticated endpoints on behalf of the victim.
 *   - CWE-352: Cross-Site Request Forgery
 *
 * VULN-2: Wildcard CORS Configuration
 *   - allowedOrigins("*") permits any origin to make cross-origin
 *     requests including reading the response.
 *   - When combined with credentials, this allows full CORS bypass.
 *   - CWE-942: Permissive Cross-domain Policy
 *
 * VULN-3: NoOpPasswordEncoder
 *   - Passwords are stored and compared in plaintext.
 *   - CWE-256: Plaintext Storage of a Password
 *
 * VULN-4: H2 Console Publicly Exposed
 *   - The in-memory DB console is accessible to all unauthenticated users,
 *     enabling full database read/write access.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // VULN-1: CSRF disabled entirely
            .csrf().disable()

            // VULN-2: Wildcard CORS
            .cors().configurationSource(corsConfigurationSource())
            .and()

            // Stateless JWT — no server-side session
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()

            .authorizeRequests()
                // VULN-4: H2 console fully open
                .antMatchers("/h2-console/**").permitAll()
                // Public endpoints
                .antMatchers("/api/auth/**", "/api/health").permitAll()
                // VULN: Admin endpoint insufficiently protected — only checks "authenticated"
                // The JwtFilter's role check is bypassable via alg:none
                .antMatchers("/api/admin/**").authenticated()
                .anyRequest().authenticated()
            .and()

            // Allow H2 Console iframes (disables X-Frame-Options)
            .headers().frameOptions().disable()
            .and()

            // Register our vulnerable JWT filter
            .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // VULN-2: Wildcard origin — allows any website to make cross-origin requests
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        // Note: allowCredentials(true) + allowedOrigins("*") would cause Spring to throw —
        // so we leave credentials false but still expose all APIs to all origins

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        // VULN-3: NoOpPasswordEncoder — passwords stored and compared in plaintext
        // Secure fix: return new BCryptPasswordEncoder(12);
        return NoOpPasswordEncoder.getInstance();
    }
}
