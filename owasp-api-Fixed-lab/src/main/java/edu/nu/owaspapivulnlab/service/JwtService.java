package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    // VULNERABILITY: app.jwt.secret is hardcoded and weak.
    // FIX: Load from environment variable (as configured in application.properties comments)
    // FIX: Convert to SecretKey once, and use it for signing and parsing.
    private final SecretKey secretKey;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    // FIX: Add issuer and audience for stronger validation
    @Value("${app.jwt.issuer:owasp-api-vuln-lab}")
    private String issuer;

    @Value("${app.jwt.audience:web-client}")
    private String audience;

    public JwtService(@Value("${app.jwt.secret}") String secret) {
        // Generate a strong key from the secret string.
        // It's crucial that the secret string itself is strong and not easily guessable.
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // VULNERABILITY(API8): HS256 with trivial key, long TTL, missing issuer/audience
    // FIX: Use SecretKey, shorter TTL, add issuer/audience.
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiration = new Date(now + ttlSeconds * 1000);

        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .setIssuer(issuer)
                .setAudience(audience)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // FIX: Add a method to parse and validate JWTs with strict checks.
    // This method will be used by our JwtFilter.
    public Claims parseToken(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .setAllowedClockSkewSeconds(5)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
