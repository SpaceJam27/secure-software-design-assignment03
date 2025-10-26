package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.stereotype.Component; // Ensure Component is imported

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component // Mark as a component so Spring manages it
public class RateLimitingFilter extends OncePerRequestFilter {

    // FIX: Make buckets static so clearBuckets can access the same map instance
    private static final Map<String, TokenBucketState> buckets = new ConcurrentHashMap<>();

    private final long capacity;
    private final long refillTokens;
    private final long refillIntervalMillis;

    public RateLimitingFilter(
            @Value("${app.rate.limit.capacity}") long capacity,
            @Value("${app.rate.limit.refill-duration-seconds}") long refillDurationSeconds,
            @Value("${app.rate.limit.refill-tokens}") long refillTokens) {
        this.capacity = capacity;
        this.refillTokens = refillTokens;
        this.refillIntervalMillis = Duration.ofSeconds(refillDurationSeconds).toMillis();
    }

    // FIX: Static method to clear buckets, directly accessing the static map
    public static void clearBuckets() {
        buckets.clear();
    }

    private static class TokenBucketState {
        private final AtomicLong tokens;
        private volatile long lastRefillTime;

        public TokenBucketState(long initialTokens) {
            this.tokens = new AtomicLong(initialTokens);
            this.lastRefillTime = System.currentTimeMillis();
        }

        public long getTokens() {
            return tokens.get();
        }

        public void setTokens(long newTokens) {
            tokens.set(newTokens);
        }

        public long getLastRefillTime() {
            return lastRefillTime;
        }

        public void setLastRefillTime(long lastRefillTime) {
            this.lastRefillTime = lastRefillTime;
        }
    }

    private TokenBucketState resolveBucket(String key) {
        return buckets.computeIfAbsent(key, k -> new TokenBucketState(capacity));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();

        boolean isSensitiveEndpoint = requestUri.startsWith("/api/auth/login") ||
                                      requestUri.matches("/api/accounts/\\d+/transfer");

        if (isSensitiveEndpoint) {
            String key;
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getName())) {
                key = "user:" + authentication.getName();
            } else {
                key = "ip:" + request.getRemoteAddr();
            }

            TokenBucketState bucketState = resolveBucket(key);

            long currentTime = System.currentTimeMillis();
            long timeElapsed = currentTime - bucketState.getLastRefillTime();

            if (timeElapsed >= refillIntervalMillis) {
                long refillsPossible = timeElapsed / refillIntervalMillis;
                long tokensToAdd = refillsPossible * refillTokens;
                bucketState.setTokens(Math.min(capacity, bucketState.getTokens() + tokensToAdd));
                bucketState.setLastRefillTime(currentTime);
            }

            if (bucketState.getTokens() > 0) {
                bucketState.setTokens(bucketState.getTokens() - 1);
                filterChain.doFilter(request, response);
            } else {
                // FIX: Ensure response is committed and explicitly handled here.
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.TEXT_PLAIN_VALUE); // Use plain text for consistency with message
                response.getWriter().write("Too many requests. Please try again later.");
                response.flushBuffer();
                return; // Crucial: terminate the filter chain here
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
