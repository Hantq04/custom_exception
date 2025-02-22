package com.example.exceptiondemo.exception;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error.", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY(1001, "Invalid message key.", HttpStatus.BAD_REQUEST),
    USER_EXISTED(1002, "Username already existed.", HttpStatus.BAD_REQUEST),
    INVALID_USERNAME(1003, "Username must be at least 4 characters.", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(1005, "Password must be at least 8 characters.", HttpStatus.BAD_REQUEST),
    NOT_BLANK(1006, "This field cannot be blank.", HttpStatus.BAD_REQUEST),
    NOT_FOUND(1007, "Data not found.", HttpStatus.NOT_FOUND),
    ROLE_NOT_FOUND(1008, "Role not found.", HttpStatus.NOT_FOUND),
    NOT_EMPTY(1009, "User must have at least 1 role.", HttpStatus.BAD_REQUEST),
    INVALID_ROLE(1010, "Invalid role.", HttpStatus.BAD_REQUEST),
    UNAUTHORIZED(1011, "You don't have permission.", HttpStatus.FORBIDDEN),
    UNAUTHENTICATED(1012, "Unauthenticated.", HttpStatus.UNAUTHORIZED),

    INVALID_JWT_TOKEN(2001, "Invalid JWT token.", HttpStatus.FORBIDDEN),
    EXPIRED_JWT_TOKEN(2002, "JWT token has expired.", HttpStatus.UNAUTHORIZED),
    UNSUPPORTED_JWT_TOKEN(2003, "Unsupported JWT token.", HttpStatus.UNAUTHORIZED),
    JWT_CLAIMS_EMPTY(2004, "JWT claims string is empty.", HttpStatus.FORBIDDEN)
    ;

    int code;
    String message;
    HttpStatusCode statusCode;
}
