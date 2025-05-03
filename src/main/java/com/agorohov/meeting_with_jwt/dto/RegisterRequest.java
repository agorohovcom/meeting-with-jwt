package com.agorohov.meeting_with_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
}
