package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import edu.nu.owaspapivulnlab.service.JwtService;
import java.io.IOException;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    private final JwtService jwtService;

    @Value("${app.rate.limit.capacity}")
    private long rateLimitCapacity;
    @Value("${app.rate.limit.refill-duration-seconds}")
    private long rateLimitRefillDurationSeconds;
    @Value("${app.rate.limit.refill-tokens}")
    private long rateLimitRefillTokens;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // FIX: RateLimitingFilter MUST be before all authentication/authorization filters
        // Place it before Spring Security's built-in filters.
        http.addFilterBefore(new RateLimitingFilter(rateLimitCapacity, rateLimitRefillDurationSeconds, rateLimitRefillTokens), org.springframework.security.web.context.SecurityContextHolderFilter.class);

        // JWT Filter after rate limit, but before Spring's core authentication
        http.addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        http.headers(h -> h.frameOptions(f -> f.disable()));

        // Configure exception handling to return JSON for 401 Unauthorized and 403 Forbidden
        // These are triggered by HttpSecurity's rules when AuthenticationEntryPoint and AccessDeniedHandler are needed
        http.exceptionHandling(eh -> eh
                .authenticationEntryPoint(jsonAuthenticationEntryPoint()) // For 401 Unauthorized (unauthenticated user tries to access protected resource)
                .accessDeniedHandler(jsonAccessDeniedHandler())        // For 403 Forbidden (authenticated user lacks permissions)
        );

        return http.build();
    }

    // Custom AuthenticationEntryPoint to return JSON 401 Unauthorized
    @Bean
    public AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Unauthorized\"}");
            response.flushBuffer();
        };
    }

    // Custom AccessDeniedHandler to return JSON 403 Forbidden
    @Bean
    public AccessDeniedHandler jsonAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Access Denied\"}");
            response.flushBuffer();
        };
    }

    // REMOVED: ExceptionTranslationFilter is no longer necessary as RateLimitingFilter explicitly returns.
    /*
    static class ExceptionTranslationFilter extends OncePerRequestFilter {
        private static final Logger logger = LoggerFactory.getLogger(ExceptionTranslationFilter.class);

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            try {
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                if (response.isCommitted()) {
                    logger.error("Exception occurred but response was already committed: {}", e.getMessage(), e);
                    return;
                }
                
                logger.error("Filter chain exception: {} for URI: {}", e.getMessage(), request.getRequestURI(), e);
                
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"An unexpected error occurred during request processing.\"}");
                response.flushBuffer();
            }
        }
    }
    */

    static class JwtFilter extends OncePerRequestFilter {
        private final JwtService jwtService;
        private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

        JwtFilter(JwtService jwtService) {
            this.jwtService = jwtService;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    Claims c = jwtService.parseToken(token);
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
                            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (ExpiredJwtException e) {
                    logger.warn("JWT expired: {}", e.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":\"JWT expired or invalid.\"}");
                    return;
                } catch (JwtException e) {
                    logger.warn("JWT validation error: {}", e.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":\"JWT expired or invalid.\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
