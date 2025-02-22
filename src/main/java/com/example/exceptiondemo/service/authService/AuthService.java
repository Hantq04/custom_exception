package com.example.exceptiondemo.service.authService;

import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.dto.JwtResponse;

public interface AuthService {
    UserDTO registerUser(UserDTO userDTO);

    JwtResponse loginUser(UserDTO userDTO);
}
