package com.agorohov.meeting_with_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserInfo {
    private String username;
    private List<String> roles;
}
