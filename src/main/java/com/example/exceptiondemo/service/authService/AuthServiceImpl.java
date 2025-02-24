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

import java.util.*;
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
            throw new AppException(ErrorCode.USER_EXISTED);
        }
        User user = userMapper.toUser(request);
        user.setUserName(user.getUserName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Set<Role> listRoles = getRolesFromRequest(request.getListRoles());
        user.setListRoles(listRoles);

        User savedUser = userService.insertUser(user);
        User persistedUser = userService.findByUserName(savedUser.getUserName());
        if (persistedUser == null) {
            throw new AppException(ErrorCode.NOT_FOUND);
        }
        // Xác thực và tạo JWT
        String jwt = authenticateAndGenerateToken(request.getUserName(), request.getPassword());
        saveUserToken(userMapper.toUserDTO(persistedUser), jwt);
        return userMapper.toUserDTO(savedUser);
    }

    private Set<Role> getRolesFromRequest(Set<String> strRoles) {
        Set<Role> listRoles = new HashSet<>();
        if (strRoles == null) {
            listRoles.add(roleService.findByRoleName(ERole.ROLE_USER)
                    .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND)));
        } else {
            strRoles.forEach(role -> {
                Role userRole = switch (role) {
                    case "admin" -> roleService.findByRoleName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));
                    case "user" -> roleService.findByRoleName(ERole.ROLE_USER)
                            .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));
                    default -> throw new AppException(ErrorCode.INVALID_ROLE);
                };
                listRoles.add(userRole);
            });
        }
        return listRoles;
    }

    private String authenticateAndGenerateToken(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        return jwtTokenProvider.generateToken(customUserDetails);
    }

    @Override
    public JwtResponse loginUser(UserDTO request) {
        String jwt = authenticateAndGenerateToken(request.getUserName(), request.getPassword());
        revokeAllUserToken(request);
        saveUserToken(request, jwt);

        User user = userService.findByUserName(request.getUserName());
        List<String> listRoles = user.getListRoles().stream()
                .map(role -> role.getRoleName().name())
                .collect(Collectors.toList());
        return new JwtResponse(jwt, getRefreshTokenFromUser(user), user.getUserName(), listRoles);
    }

    private String getRefreshTokenFromUser(User user) {
        return tokenRepo.findAllValidTokensByUser(user.getUserId()).stream()
                .findFirst()
                .map(Token::getRefreshToken)
                .orElse(UUID.randomUUID().toString());
    }

    private void saveUserToken(UserDTO userDTO, String jwtToken) {
        User user = userService.findByUserName(userDTO.getUserName());
        if (user == null) {
            throw new AppException(ErrorCode.NOT_FOUND);
        }
        Date now = new Date();
        Date dateRefreshExpire = new Date(now.getTime() + jwtTokenProvider.getRefreshExpiration());
        Date dateExpire = new Date(now.getTime() + jwtTokenProvider.getJWT_EXPIRATION());
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        token.setExpireToken(dateExpire);
        token.setRefreshToken(UUID.randomUUID().toString());
        token.setRefreshExpirationDate(dateRefreshExpire);
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

    public JwtResponse refreshToken(String refreshToken) {
        Token token = tokenRepo.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new AppException(ErrorCode.NOT_FOUND));
        if (token.isExpired() || token.isRevoked()) {
            throw new AppException(ErrorCode.EXPIRED_JWT_TOKEN);
        }
        User user = token.getUser();
        CustomUserDetails customUserDetails = CustomUserDetails.mapUserToUserDetail(user);
        // Tạo access token mới
        String newAccessToken = jwtTokenProvider.generateToken(customUserDetails);
        // Cập nhật refresh token nếu đã hết hạn
        String newRefreshToken = token.getRefreshToken();
        Date now = new Date();
        if (token.getRefreshExpirationDate().before(now)) {
            newRefreshToken = UUID.randomUUID().toString();
            Date newRefreshExpiration = new Date(now.getTime() + jwtTokenProvider.getRefreshExpiration());
            token.setRefreshToken(newRefreshToken);
            token.setRefreshExpirationDate(newRefreshExpiration);
        }
        token.setToken(newAccessToken);
        tokenRepo.save(token);
        List<String> listRoles = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return new JwtResponse(newAccessToken, newRefreshToken, user.getUserName(), listRoles);
    }
}
