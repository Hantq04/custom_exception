package com.example.exceptiondemo.service.authService;

import com.example.exceptiondemo.config.jwt.JwtTokenProvider;
import com.example.exceptiondemo.config.security.CustomUserDetails;
import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.enums.ERole;
import com.example.exceptiondemo.enums.TokenType;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.exception.ErrorCode;
import com.example.exceptiondemo.mapper.UserMapper;
import com.example.exceptiondemo.model.Role;
import com.example.exceptiondemo.model.Token;
import com.example.exceptiondemo.model.User;
import com.example.exceptiondemo.dto.JwtResponse;
import com.example.exceptiondemo.repository.TokenRepo;
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
    TokenRepo tokenRepo;

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
        User savedUser = userService.insertUser(user);

        User persistedUser = userService.findByUserName(savedUser.getUserName());
        if (persistedUser == null) {
            throw new AppException(ErrorCode.NOT_FOUND);
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtTokenProvider.generateToken(customUserDetails);
        saveUserToken(userMapper.toUserDTO(persistedUser), jwt);

        return userMapper.toUserDTO(savedUser);
    }

    @Override
    public JwtResponse loginUser(UserDTO request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtTokenProvider.generateToken(customUserDetails);
        revokeAllUserToken(request);
        saveUserToken(request, jwt);
        List<String> listRoles = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return new JwtResponse(jwt, customUserDetails.getUsername(), listRoles);
    }

    private void saveUserToken(UserDTO userDTO, String jwtToken) {
        User user = userService.findByUserName(userDTO.getUserName());
        if (user == null) {
            throw new AppException(ErrorCode.NOT_FOUND);
        }
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepo.save(token);
    }

    private void revokeAllUserToken(UserDTO userDTO) {
        User user = userService.findByUserName(userDTO.getUserName());
        if (user == null) {
            throw new AppException(ErrorCode.NOT_FOUND);
        }
        var validUserTokens = tokenRepo.findAllValidTokensByUser(user.getUserId());
        if (validUserTokens.isEmpty()) return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepo.saveAll(validUserTokens);
    }
}
