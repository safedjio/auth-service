package com.safedjio.authservice.security;

import com.safedjio.authservice.entity.Role;
import com.safedjio.authservice.exception.InvalidTokenException;
import com.safedjio.authservice.exception.TokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final JwtProperties jwtProperties;

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Long userId, Role role) {
        return buildToken(userId, role, TYPE_ACCESS,
                jwtProperties.getAccessTokenTtlMinutes(), ChronoUnit.MINUTES);
    }

    public String generateRefreshToken(Long userId, Role role) {
        return buildToken(userId, role, TYPE_REFRESH,
                jwtProperties.getRefreshTokenTtlDays(), ChronoUnit.DAYS);
    }

    private String buildToken(Long userId, Role role, String type, long amount, ChronoUnit unit) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim(CLAIM_ROLE, role.name())
                .claim(CLAIM_TYPE, type)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(amount, unit)))
                .signWith(signingKey())
                .compact();
    }

    public Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Token is invalid");
        }
    }

    public Claims parseAccessTokenClaims(String token) {
        Claims claims = parseClaims(token);
        requireType(claims, TYPE_ACCESS);
        return claims;
    }

    public Claims parseRefreshTokenClaims(String token) {
        Claims claims = parseClaims(token);
        requireType(claims, TYPE_REFRESH);
        return claims;
    }

    private void requireType(Claims claims, String expectedType) {
        Object actualType = claims.get(CLAIM_TYPE);
        if (!expectedType.equals(actualType)) {
            throw new InvalidTokenException("Unexpected token type: expected " + expectedType);
        }
    }

    public Long extractUserId(Claims claims) {
        return Long.valueOf(claims.getSubject());
    }

    public Role extractRole(Claims claims) {
        return Role.valueOf(claims.get(CLAIM_ROLE, String.class));
    }
}
