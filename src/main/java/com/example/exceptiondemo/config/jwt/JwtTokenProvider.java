package com.example.exceptiondemo.config.jwt;

import com.example.exceptiondemo.config.security.CustomUserDetails;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE)
public class JwtTokenProvider {
    @Value("${application.jwt.secret}")
    String JWT_SECRET;
    @Value("${application.jwt.expiration}")
    Integer JWT_EXPIRATION;

    public String generateToken(CustomUserDetails customUserDetails) {
        Date now = new Date();
        Date dateExpire = new Date(now.getTime() + JWT_EXPIRATION);
        SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes());
        return Jwts.builder()
                .setSubject(customUserDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(dateExpire)
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public String getUserNameFromJwt(String token) {
        SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes());
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public void validateToken(String authToken) {
        SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes());
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(authToken);
        } catch (MalformedJwtException e) {
            throw new AppException(ErrorCode.INVALID_JWT_TOKEN);
        } catch (ExpiredJwtException e) {
            throw new AppException(ErrorCode.EXPIRED_JWT_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new AppException(ErrorCode.UNSUPPORTED_JWT_TOKEN);
        } catch (IllegalArgumentException e) {
            throw new AppException(ErrorCode.JWT_CLAIMS_EMPTY);
        }
    }
}
