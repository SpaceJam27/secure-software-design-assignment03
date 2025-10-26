# OWASP API Vulnerable Lab (Spring Boot + JWT)

> This project intentionally contains vulnerabilities mapped to **OWASP API Security Top 10 (2023)** 
> so students can identify and fix them.

## Quick Start

```bash
# Java 17 + Maven required
mvn spring-boot:run
# H2 Console: http://localhost:8080/h2-console (JDBC URL: jdbc:h2:mem:apilab)
```

## Seed Users

- `alice / alice123` (USER)
- `bob / bob123` (ADMIN)

Login to get a JWT:
```bash
curl -s -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice123"}'
# => {"token":"<JWT>"}
```

Use the token:
```bash
export T="<JWT>"
curl -H "Authorization: Bearer $T" http://localhost:8080/api/accounts/mine
```

## Intentional Vulnerabilities

- **API1: Broken Object Level Authorization (BOLA/IDOR)**
- **API2: Broken Authentication**
- **API3: Excessive Data Exposure**
- **API4: Unrestricted Resource Consumption**
- **API5: Broken Function Level Authorization**
- **API6: Mass Assignment**
- **API7: Security Misconfiguration**
- **API8: Weak Authentication / JWT issues**
- **API9: Improper Inventory / Injection-like search**
- **API10: Unsafe Consumption of APIs** (discussion prompt)

## Student Tasks (Fixes)
1. Replace plaintext passwords with BCrypt; add signup flow and migrate existing seeds.
2. Tighten `SecurityFilterChain`: remove `permitAll` on `/api/**`, require auth; enforce role checks.
3. In controllers, enforce ownership: user can only access their own resources (map subject -> userId).
4. Implement DTOs to control data exposure; never return password, role, or admin flags.
5. Add rate limiting (Bucket4j/Resilience4j) to sensitive endpoints.
6. Prevent Mass Assignment: use explicit request DTOs without `role`, `isAdmin` or validate them server-side.
7. Harden JWT: strong key from env, short TTL, add issuer/audience, validate signature & expiry strictly.
8. Reduce error detail in production; proper exception mapping and logging.
9. Add input validation; reject negative or huge transfers.
10. Add integration tests to capture fixed behavior.

## Notes
- Keep a list of fixes and submit a PR describing how each vulnerability was addressed.
