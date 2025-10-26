package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    // VULNERABILITY(API3: Excessive Data Exposure): storing plaintext passwords for demo
    // Students should hash with BCrypt and use proper credential storage.
    @NotBlank
    private String password;

    // VULNERABILITY(API6: Mass Assignment): role and isAdmin are bindable via incoming JSON
    private String role;   // e.g., "USER" or "ADMIN"
    private boolean isAdmin;

    @Email
    private String email;
}
