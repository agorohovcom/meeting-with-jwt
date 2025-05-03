package com.agorohov.meeting_with_jwt.controller;

import com.agorohov.meeting_with_jwt.dto.AuthenticationRequest;
import com.agorohov.meeting_with_jwt.dto.AuthenticationResponse;
import com.agorohov.meeting_with_jwt.dto.RefreshRequest;
import com.agorohov.meeting_with_jwt.dto.RegisterRequest;
import com.agorohov.meeting_with_jwt.dto.UserDto;
import com.agorohov.meeting_with_jwt.dto.UserInfo;
import com.agorohov.meeting_with_jwt.service.InMemoryUserDetailsService;
import com.agorohov.meeting_with_jwt.service.JwtTokenBlacklistService;
import com.agorohov.meeting_with_jwt.util.JwtUtils;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final InMemoryUserDetailsService userDetailsService;
    private final JwtTokenBlacklistService blacklistService;
    private final JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest request) {
        log.info("Login attempt: username={}, password={}", request.getUsername(), request.getPassword());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            UserDetails ud = (UserDetails) authentication.getPrincipal();

            String accessToken = jwtUtils.generateAccessToken(ud);
            String refreshToken = jwtUtils.generateRefreshToken(ud);

            return ResponseEntity.ok(new AuthenticationResponse(accessToken, refreshToken));
        } catch (BadCredentialsException e) {
            String msg = String.format("Authentication failed for %s", request.getUsername());
            log.error(msg);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(msg);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        UserDetails ud;
        try {
            ud = userDetailsService.loadUserByUsername(jwtUtils.extractUsername(refreshToken));
        } catch (JwtException e) {
            String msg = "Malformed refresh token";
            log.error(msg);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(msg);
        }

        if (!jwtUtils.validateToken(refreshToken, ud) || blacklistService.isTokenBlacklisted(refreshToken)) {
            String msg = "Refresh token is invalid or invalidated (blacklisted)";
            log.error(msg);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(msg);
        }

        String newAccessToken = jwtUtils.generateAccessToken(ud);
        String newRefreshToken = jwtUtils.generateRefreshToken(ud);

        blacklistService.blacklistToken(refreshToken);

        log.info("Token refreshed successfully");
        return ResponseEntity.ok(new AuthenticationResponse(newAccessToken, newRefreshToken));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        if (userDetailsService.userExists(registerRequest.getUsername())) {
            String msg = String.format("Username already exists: %s", registerRequest.getUsername());
            log.error(msg);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(msg);
        }

        String username = registerRequest.getUsername();

        UserDto dto = new UserDto(username, registerRequest.getPassword(), List.of("USER"));
        userDetailsService.addUser(dto);

        UserDetails ud = userDetailsService.loadUserByUsername(username);

        String accessToken = jwtUtils.generateAccessToken(ud);
        String refreshToken = jwtUtils.generateRefreshToken(ud);

        log.info("New user registered successfully: {}", username);
        return ResponseEntity.ok(new AuthenticationResponse(accessToken, refreshToken));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        UserDetails ud = (UserDetails) authentication.getPrincipal();
        var response = ResponseEntity.ok(new UserInfo(
                ud.getUsername(),
                ud.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .map(role -> role.replaceFirst("^ROLE_", ""))
                        .toList()
        ));

        log.info("User self info received: {} ", ud.getUsername());
        return response;
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            blacklistService.blacklistToken(token);
        }
        String msg = "Logged out successfully";
        log.info(msg);
        return ResponseEntity.ok(msg);
    }
}
