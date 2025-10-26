package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size; // Import Size annotation
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder; // Import PasswordEncoder

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder; // Inject PasswordEncoder

    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) { // Update constructor
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder; // Assign PasswordEncoder
    }

    public static class LoginReq {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters") // FIX: Add size validation
        private String username;

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters") // FIX: Add size validation
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginReq req) { // FIX: Add @Valid annotation here
        AppUser user = users.findByUsername(req.username()).orElse(null);
        // VULNERABILITY(API2: Broken Authentication): plaintext password check, no lockout/rate limit/MFA
        // FIX: Use BCrypt for password comparison
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin()); // VULN: trusts client-side role later
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    // If you have a signup endpoint, it would look something like this:
    /*
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody @Valid LoginReq req) { // Add @Valid for signup as well
        if (users.findByUsername(req.username()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "username already taken");
            return ResponseEntity.status(409).body(error); // 409 Conflict
        }
        AppUser newUser = AppUser.builder()
                .username(req.username())
                .password(passwordEncoder.encode(req.password())) // Hash password
                .role("USER") // Default role
                .isAdmin(false)
                .build();
        users.save(newUser);
        return ResponseEntity.ok().build();
    }
    */
}
