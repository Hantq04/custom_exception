package com.example.exceptiondemo.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
public class JwtResponse {
    String token;
    String refreshToken;
    String type = "Bearer ";
    String userName;
    List<String> listRoles;

    public JwtResponse(String token, String refreshToken, String userName, List<String> listRoles) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.userName = userName;
        this.listRoles = listRoles;
    }
}
