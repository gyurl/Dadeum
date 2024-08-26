package com.hkit.stt.jwt;

import lombok.Data;

@Data
public class LoginRequest {
    private String id;
    private String password;
}
