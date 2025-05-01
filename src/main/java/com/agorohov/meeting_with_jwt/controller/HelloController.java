package com.agorohov.meeting_with_jwt.controller;

import com.agorohov.meeting_with_jwt.service.InMemoryUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
@RequiredArgsConstructor
public class HelloController {

    private final InMemoryUserDetailsService userDetailsService;

    @GetMapping
    public ResponseEntity<String> hello(Authentication authentication) {
        return ResponseEntity.ok("Hello, " + authentication.getName() + "! =)");
    }
}
