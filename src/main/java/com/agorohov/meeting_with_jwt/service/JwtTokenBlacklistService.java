package com.agorohov.meeting_with_jwt.service;

import com.agorohov.meeting_with_jwt.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class JwtTokenBlacklistService {

    private final JwtUtils jwtUtils;

    private final Map<String, Instant> blacklist = new ConcurrentHashMap<>();

    public void blacklistToken(String token) {
        Instant expiration = jwtUtils.extractExpiration(token);
        blacklist.put(token, expiration);
    }

    public boolean isTokenBlacklisted(String token) {
        Instant expiration = blacklist.get(token);
        return expiration != null && expiration.isAfter(Instant.now());
    }

    @Scheduled(fixedRateString = "${jwt.blacklist.cleanup.interval:60000}")
    public void removeExpiredTokens() {
        Instant now = Instant.now();
        blacklist.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }
}
