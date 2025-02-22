package com.example.exceptiondemo.exception;

import com.example.exceptiondemo.util.ResponseObject;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.validation.FieldError;

import java.util.Arrays;

@ControllerAdvice
@Slf4j
@RequiredArgsConstructor
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseObject> handleException(Exception exception) {
        ErrorCode errorCode;

        if (exception instanceof AppException appException) {
            return ResponseEntity.status(appException.getErrorCode().getStatusCode()).body(
                    new ResponseObject(appException.getErrorCode().getCode(), appException.getMessage(), "")
            );
        }

        if (exception instanceof MethodArgumentNotValidException e) {
            FieldError fieldError = e.getFieldError();
            errorCode = ErrorCode.INVALID_KEY;

            if (fieldError != null) {
                String enumKey = fieldError.getDefaultMessage();
                try {
                    errorCode = ErrorCode.valueOf(enumKey);
                } catch (IllegalArgumentException ex) {
                    log.error("Exception: {}", ex.getMessage());
                }
            }

            return ResponseEntity.status(e.getStatusCode()).body(
                    new ResponseObject(errorCode.getCode(), errorCode.getMessage(), "")
            );
        }

        if (exception instanceof BadCredentialsException) {
            errorCode = ErrorCode.UNAUTHENTICATED;
            log.info("ERROR :: BadCredentials");
        } else if (exception instanceof AccessDeniedException || exception instanceof UsernameNotFoundException) {
            errorCode = ErrorCode.UNAUTHORIZED;
            log.info("ERROR :: DENIED");
        } else if (exception instanceof ExpiredJwtException) {
            errorCode = ErrorCode.EXPIRED_JWT_TOKEN;
            log.info("ERROR :: Expired JWT Token");
        } else if (exception instanceof MalformedJwtException) {
            errorCode = ErrorCode.INVALID_JWT_TOKEN;
            log.info("ERROR :: Malformed JWT Token");
        } else if (exception instanceof UnsupportedJwtException) {
            errorCode = ErrorCode.UNSUPPORTED_JWT_TOKEN;
            log.info("ERROR :: Unsupported JWT Token");
        } else {
            log.error("Unhandled exception: {}", exception.getMessage());
            errorCode = ErrorCode.UNCATEGORIZED_EXCEPTION;
        }
        log.error("Error Location: {}", Arrays.toString(Arrays.copyOfRange(exception.getStackTrace(), 0, 3)));
        return ResponseEntity.status(errorCode.getStatusCode()).body(
                new ResponseObject(errorCode.getCode(), errorCode.getMessage(), "")
        );
    }
}
