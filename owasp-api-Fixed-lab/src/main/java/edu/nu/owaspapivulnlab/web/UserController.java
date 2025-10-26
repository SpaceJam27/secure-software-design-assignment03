package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.DTO.UserDTO;
import edu.nu.owaspapivulnlab.DTO.UserCreationRequestDTO;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    private Long getAuthenticatedUserId(Authentication auth) {
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getName())) {
            return null;
        }
        return users.findByUsername(auth.getName())
                .map(AppUser::getId)
                .orElse(null);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        Long authenticatedUserId = getAuthenticatedUserId(auth);
        if (authenticatedUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Unauthorized"));
        }

        AppUser user = users.findById(id).orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "Resource not found"));
        }

        if (!user.getId().equals(authenticatedUserId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Collections.singletonMap("error", "Access denied"));
        }

        return ResponseEntity.ok(new UserDTO(user.getId(), user.getUsername(), user.getEmail()));
    }

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody UserCreationRequestDTO request) {
        if (users.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Collections.singletonMap("error", "Username already taken"));
        }

        AppUser newUser = AppUser.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role("USER")
                .isAdmin(false)
                .build();

        newUser = users.save(newUser);
        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(newUser.getId(), newUser.getUsername(), newUser.getEmail()));
    }

    @GetMapping("/search")
    public List<UserDTO> search(@RequestParam String q) {
        return users.search(q).stream()
                .map(user -> new UserDTO(user.getId(), user.getUsername(), user.getEmail()))
                .collect(Collectors.toList());
    }

    @GetMapping
    public List<UserDTO> list() {
        return users.findAll().stream()
                .map(user -> new UserDTO(user.getId(), user.getUsername(), user.getEmail()))
                .collect(Collectors.toList());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        Long authenticatedUserId = getAuthenticatedUserId(auth);
        if (authenticatedUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Unauthorized"));
        }

        AppUser userToDelete = users.findById(id).orElse(null);
        if (userToDelete == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "Resource not found"));
        }

        if (!auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Collections.singletonMap("error", "Access denied. Only ADMINs can delete users."));
        }

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
