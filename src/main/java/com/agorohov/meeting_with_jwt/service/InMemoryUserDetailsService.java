package com.agorohov.meeting_with_jwt.service;

import com.agorohov.meeting_with_jwt.dto.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class InMemoryUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return User.withUserDetails(user).build();
    }

    public void addUser(UserDto dto) {
        if (users.containsKey(dto.getUsername())) {
            throw new IllegalArgumentException("User already exists: " + dto.getUsername());
        }

        String encodedPassword = passwordEncoder.encode(dto.getPassword());
        UserDetails user = User.builder()
                .username(dto.getUsername())
                .password(encodedPassword)
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
