package com.agorohov.meeting_with_jwt.service;

import com.agorohov.meeting_with_jwt.dto.UserDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class InMemoryUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }

    public void addUser(UserDto dto) {
        if (users.containsKey(dto.getUsername())) {
            throw new IllegalArgumentException("User already exists: " + dto.getUsername());
        }
        UserDetails user = User.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .roles(dto.getRoles().toArray(new String[0]))
                .build();

        users.put(dto.getUsername(), user);
    }

    public void removeUser(String username) {
        if (!users.containsKey(username)) {
            throw new IllegalArgumentException("User not found: " + username);
        }
        users.remove(username);
    }

    public boolean userExists(String username) {
        return users.containsKey(username);
    }

    public void clearUsers() {
        users.clear();
    }

    // Защитная копия
    public Map<String, UserDetails> getAllUsers() {
        return Map.copyOf(users);
    }
}
