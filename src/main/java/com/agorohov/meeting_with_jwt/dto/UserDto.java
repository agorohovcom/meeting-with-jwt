package com.agorohov.meeting_with_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserDto {
    private String username;
    private String password;
    private List<String> roles;
}
