package com.agorohov.meeting_with_jwt.util;

import com.agorohov.meeting_with_jwt.dto.UserDto;
import com.agorohov.meeting_with_jwt.service.InMemoryUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class TestUserLoader implements CommandLineRunner {

    private final InMemoryUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (!userDetailsService.userExists("user")) {
            userDetailsService.addUser(new UserDto(
                    "user",
                    "password",
                    List.of("USER")
            ));
        }

        if (!userDetailsService.userExists("admin")) {
            userDetailsService.addUser(new UserDto(
                    "admin",
                    "admin123",
                    List.of("ADMIN")
            ));
        }

        log.info("✅ Test users added (user/password, admin/admin123)");
    }
}
