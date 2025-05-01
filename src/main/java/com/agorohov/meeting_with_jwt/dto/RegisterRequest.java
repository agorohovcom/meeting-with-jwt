package com.agorohov.meeting_with_jwt.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String password;
}
