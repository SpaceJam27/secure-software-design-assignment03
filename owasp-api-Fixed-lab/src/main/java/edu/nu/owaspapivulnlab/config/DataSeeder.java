package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts) {
        return args -> {
            if (users.count() == 0) {
                // Use longer passwords for seeded users to satisfy new validation rules
                AppUser alice = AppUser.builder()
                        .username("alice")
                        .password(passwordEncoder.encode("alice12345"))
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build();
                AppUser bob = AppUser.builder()
                        .username("bob")
                        .password(passwordEncoder.encode("bob12345"))
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build();

                alice = users.save(alice);
                bob = users.save(bob);

                accounts.save(Account.builder()
                        .ownerUserId(alice.getId())
                        .iban("PK00-ALICE")
                        .balance(1000.0)
                        .build());
                accounts.save(Account.builder()
                        .ownerUserId(bob.getId())
                        .iban("PK00-BOB")
                        .balance(5000.0)
                        .build());
            }
        };
    }
}
