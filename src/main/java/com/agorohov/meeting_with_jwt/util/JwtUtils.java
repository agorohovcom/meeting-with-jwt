package com.agorohov.meeting_with_jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access.expiration.ms}")
    private long accessExpiration;

    @Value("${jwt.refresh.expiration.ms}")
    private long refreshExpiration;

    private SecretKey signingKey;

    @PostConstruct
    private void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // Извлечь имя пользователя из токена
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Извлечь срок жизни токена
    public Instant extractExpiration(String token) {
        Date expirationDate = extractClaim(token, Claims::getExpiration);
        return expirationDate.toInstant();
    }

    // Общий метод для извлечения данных
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Проверить, истекло ли время действия токена
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(Instant.now());
    }

    // Сгенерировать access токен для пользователя
    public String generateAccessToken(UserDetails user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return createToken(claims, user.getUsername(), accessExpiration);
    }

    // Сгенерировать refresh токен для пользователя
    public String generateRefreshToken(UserDetails user) {
        return createToken(Map.of(), user.getUsername(), refreshExpiration);
    }

    // Создать токен
    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(signingKey)
                .compact();
    }

    // Валидация токена
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        try {
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (JwtException e) {
            return false;
        }
    }

    // Парсинг токена
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new RuntimeException("Invalid JWT token", e);
        }
    }
}
