package com.example.exceptiondemo.service.authService;

import com.example.exceptiondemo.config.jwt.JwtTokenProvider;
import com.example.exceptiondemo.config.security.CustomUserDetails;
import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.enums.ERole;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.exception.ErrorCode;
import com.example.exceptiondemo.mapper.UserMapper;
import com.example.exceptiondemo.model.Role;
import com.example.exceptiondemo.model.User;
import com.example.exceptiondemo.dto.JwtResponse;
import com.example.exceptiondemo.service.roleService.RoleServiceImpl;
import com.example.exceptiondemo.service.userService.UserServiceImpl;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthServiceImpl implements AuthService{
    AuthenticationManager authenticationManager;
    JwtTokenProvider jwtTokenProvider;
    UserServiceImpl userService;
    RoleServiceImpl roleService;
    PasswordEncoder passwordEncoder;
    UserMapper userMapper;

    @Override
    public UserDTO registerUser(UserDTO request) {
        if (userService.existsByUserName(request.getUserName())) {
            throw  new AppException(ErrorCode.USER_EXISTED);
        }
        User user = userMapper.toUser(request);
        user.setUserName(user.getUserName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Set<String> strRoles = request.getListRoles();
        Set<Role> listRoles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleService.findByRoleName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("ROLE_NOT_FOUND."));
            listRoles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleService.findByRoleName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));
                        listRoles.add(adminRole);
                        break;
                    case "user":
                        Role userRole = roleService.findByRoleName(ERole.ROLE_USER)
                                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));
                        listRoles.add(userRole);
                        break;
                    default:
                        throw new AppException(ErrorCode.INVALID_ROLE);
                }
            });
        }
        user.setListRoles(listRoles);
        User saveUser = userService.insertUser(user);
        return userMapper.toUserDTO(saveUser);
    }

    @Override
    public JwtResponse loginUser(UserDTO request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtTokenProvider.generateToken(customUserDetails);
        List<String> listRoles = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return new JwtResponse(jwt, customUserDetails.getUsername(), listRoles);
    }
}
