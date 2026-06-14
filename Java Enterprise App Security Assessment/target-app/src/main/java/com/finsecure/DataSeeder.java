package com.finsecure;

import com.finsecure.model.Account;
import com.finsecure.model.User;
import com.finsecure.repository.AccountRepository;
import com.finsecure.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Seeds the H2 in-memory database with realistic demo data on startup.
 * This gives DAST tools real accounts to test IDOR against.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final AccountRepository accountRepository;
    private final UserRepository userRepository;

    public DataSeeder(AccountRepository accountRepository, UserRepository userRepository) {
        this.accountRepository = accountRepository;
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) {
        // Seed users — VULN: passwords in plaintext
        userRepository.save(new User("alice",    "alice123",   "alice@finsecure.com",   "USER"));
        userRepository.save(new User("bob",      "bob456",     "bob@finsecure.com",     "USER"));
        userRepository.save(new User("charlie",  "charlie789", "charlie@finsecure.com", "USER"));
        userRepository.save(new User("admin",    "admin@123",  "admin@finsecure.com",   "ADMIN"));

        // Seed accounts — IDOR test targets (IDs 1-4 belong to different users)
        accountRepository.save(new Account("ACC-001", "Alice Johnson",   "alice@finsecure.com",   125_430.50));
        accountRepository.save(new Account("ACC-002", "Bob Martinez",    "bob@finsecure.com",     78_250.00));
        accountRepository.save(new Account("ACC-003", "Charlie Davis",   "charlie@finsecure.com", 342_100.75));
        accountRepository.save(new Account("ACC-004", "Admin User",      "admin@finsecure.com",   9_999_999.00));

        System.out.println("[DataSeeder] Seeded 4 users and 4 accounts.");
        System.out.println("[DataSeeder] Login: alice / alice123 | bob / bob456 | admin / admin@123");
    }
}
