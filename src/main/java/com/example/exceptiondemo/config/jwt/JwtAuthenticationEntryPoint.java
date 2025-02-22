package com.example.exceptiondemo.config.jwt;

import com.example.exceptiondemo.exception.ErrorCode;
import com.example.exceptiondemo.util.ResponseObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        ErrorCode errorCode = ErrorCode.UNAUTHENTICATED;

        response.setStatus(errorCode.getStatusCode().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ResponseObject responseError = new ResponseObject(
                errorCode.getCode(), errorCode.getMessage(), authException.getMessage());

        ObjectMapper objectMapper = new ObjectMapper();
        // response data form
        response.getWriter().write(objectMapper.writeValueAsString(responseError));
        response.flushBuffer();
    }
}
