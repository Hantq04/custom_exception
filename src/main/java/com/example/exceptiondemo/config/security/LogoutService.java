package com.example.exceptiondemo.config.security;

import com.example.exceptiondemo.repository.TokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private static final Logger logger = Logger.getLogger(LogoutService.class.getName());
    private final TokenRepo tokenRepo;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        logger.info("-------- Logout --------");
        final var authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        var jwt = authHeader.substring(7);
        var storedToken = tokenRepo.findByToken(jwt)
                .orElse(null);
        if (storedToken != null) {
            logger.info("Token found, updating status...");
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepo.save(storedToken);
            logger.info("Token status updated: Expired = " + storedToken.isExpired() + ", Revoked = " + storedToken.isRevoked());
        } else {
            logger.warning("Token not found in database!");
        }
    }
}
