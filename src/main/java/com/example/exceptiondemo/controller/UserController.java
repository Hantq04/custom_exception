package com.example.exceptiondemo.controller;

import com.example.exceptiondemo.dto.JwtResponse;
import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.groupValidate.DeleteUser;
import com.example.exceptiondemo.groupValidate.InsertUser;
import com.example.exceptiondemo.groupValidate.LoginUser;
import com.example.exceptiondemo.service.authService.AuthService;
import com.example.exceptiondemo.service.userService.UserService;
import com.example.exceptiondemo.util.ResponseObject;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class UserController {
    private static final Logger logger = Logger.getLogger(UserController.class.getName());
    private final UserService userService;
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ResponseObject> registerUser(@Validated(InsertUser.class) @RequestBody UserDTO userDTO) {
        UserDTO responseData = authService.registerUser(userDTO);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ResponseObject(HttpStatus.OK, "Register user successfully.", responseData)
        );
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseObject> loginUser(@Validated(LoginUser.class) @RequestBody UserDTO userDTO) {
        logger.info("-------- Login page --------");
        JwtResponse responseData = authService.loginUser(userDTO);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ResponseObject(HttpStatus.OK, "User login successfully.", responseData)
        );
    }

    @DeleteMapping("/delete")
    public ResponseEntity<ResponseObject> deleteUser(@Validated(DeleteUser.class) @RequestParam List<Integer> listUser) {
        try {
            userService.deleteUser(listUser);
            return ResponseEntity.status(HttpStatus.OK).body(
                    new ResponseObject(HttpStatus.OK, "Delete user successfully.", "")
            );
        } catch (DataIntegrityViolationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    new ResponseObject(HttpStatus.BAD_REQUEST, "Cannot delete user due to existing relationships.", "")
            );
        }
    }

    @GetMapping("/get-user-list")
    public ResponseEntity<ResponseObject> getUserList() {
        return ResponseEntity.status(HttpStatus.OK).body(
                new ResponseObject(HttpStatus.OK, "", userService.getUserList())
        );
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseObject> refreshToken(@Valid @RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");
            JwtResponse jwtResponse = authService.refreshToken(refreshToken);
            return ResponseEntity.status(HttpStatus.OK)
                    .body(new ResponseObject(HttpStatus.OK, "Token refreshed successfully", jwtResponse));
        } catch (AppException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseObject(HttpStatus.UNAUTHORIZED, e.getMessage(), ""));
        }
    }
}
