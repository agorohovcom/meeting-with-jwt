package com.agorohov.meeting_with_jwt.controller;

import com.agorohov.meeting_with_jwt.dto.AuthenticationRequest;
import com.agorohov.meeting_with_jwt.dto.AuthenticationResponse;
import com.agorohov.meeting_with_jwt.dto.RegisterRequest;
import com.agorohov.meeting_with_jwt.dto.UserDto;
import com.agorohov.meeting_with_jwt.service.InMemoryUserDetailsService;
import com.agorohov.meeting_with_jwt.service.JwtTokenBlacklistService;
import com.agorohov.meeting_with_jwt.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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

            String jwt = jwtUtils.generateToken((UserDetails) authentication.getPrincipal());
            return ResponseEntity.ok(new AuthenticationResponse(jwt));
        } catch (BadCredentialsException e) {
            String msg = String.format("Authentication failed for %s", request.getUsername());
            log.error(msg);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(msg);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        if (userDetailsService.userExists(registerRequest.getUsername())) {
            String msg = String.format("Username already exists: %s", registerRequest.getUsername());
            log.error(msg);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(msg);
        }

        UserDto dto = new UserDto(registerRequest.getUsername(), registerRequest.getPassword(), List.of("USER"));
        userDetailsService.addUser(dto);
        String token = jwtUtils.generateToken(userDetailsService.loadUserByUsername(registerRequest.getUsername()));
        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            blacklistService.blacklistToken(token);
            SecurityContextHolder.clearContext();
        }
        return ResponseEntity.ok("Logged out successfully");
    }

    // TODO что такое /refresh, /me, 2FA
}
