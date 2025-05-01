package com.agorohov.meeting_with_jwt.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
public class InMemoryUserDetailsService implements UserDetailsService {

    // TODO может тут конкаррентхешмап?
    private final Map<String, UserDetails> users = new HashMap<>();

    // Конструктор для добавления юзеров в память
    public InMemoryUserDetailsService() {
        users.put("user", new User(
                "user",
                "{noop}password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        ));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found by username: " + username);
        }
        return user;
    }
}
