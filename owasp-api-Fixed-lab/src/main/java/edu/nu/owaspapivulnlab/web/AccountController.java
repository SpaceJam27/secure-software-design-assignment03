package edu.nu.owaspapivulnlab.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.DTO.AccountDTO; // Import AccountDTO
import edu.nu.owaspapivulnlab.DTO.TransferRequestDTO; // Import the validated DTO

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import jakarta.validation.Valid; // For request body validation

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // Helper method to get the authenticated user's ID
    private Long getAuthenticatedUserId(Authentication auth) {
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getName())) {
            return null;
        }
        return users.findByUsername(auth.getName())
                .map(AppUser::getId)
                .orElse(null);
    }

    // VULNERABILITY(API1: BOLA) - no check whether account belongs to caller
    // FIX: Enforce resource ownership
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Long authenticatedUserId = getAuthenticatedUserId(auth);
        if (authenticatedUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Unauthorized"));
        }

        Account a = accounts.findById(id)
                .orElse(null); // Use null instead of throwing directly for custom error handling

        if (a == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "Account not found"));
        }

        // Check if the authenticated user is the owner of the account
        if (!Objects.equals(a.getOwnerUserId(), authenticatedUserId)) {
            // VULNERABILITY(API1: BOLA) - Return 403 Forbidden for unauthorized access
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Collections.singletonMap("error", "Access denied"));
        }

        return ResponseEntity.ok(a.getBalance());
    }

    // VULNERABILITY(API4: Unrestricted Resource Consumption) - no rate limiting on transfer
    // VULNERABILITY(API5/1): no authorization check on owner
    // FIX: Enforce resource ownership and add placeholder for rate limiting (Task 5)
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestBody @Valid TransferRequestDTO transferRequest, Authentication auth) {
        Long authenticatedUserId = getAuthenticatedUserId(auth);
        if (authenticatedUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Unauthorized"));
        }

        Account a = accounts.findById(id)
                .orElse(null); // Use null instead of throwing directly for custom error handling

        if (a == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "Account not found"));
        }

        // Check if the authenticated user is the owner of the account
        if (!Objects.equals(a.getOwnerUserId(), authenticatedUserId)) {
            // VULNERABILITY(API1: BOLA) - Return 403 Forbidden for unauthorized access
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Collections.singletonMap("error", "Access denied"));
        }

        Double amount = transferRequest.getAmount();
        // Note: further validation for upper limits or business rules can be added here

        if (a.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Insufficient balance"));
        }
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    // FIX: Return a list of AccountDTOs instead of Account entities.
    @GetMapping("/mine")
    public List<AccountDTO> mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        if (me == null) {
            return Collections.emptyList();
        }
        return accounts.findByOwnerUserId(me.getId()).stream()
                .map(account -> new AccountDTO(account.getId(), account.getIban(), account.getBalance()))
                .collect(Collectors.toList());
    }
}
