package com.example.exceptiondemo.util;

import com.example.exceptiondemo.exception.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ResponseObject {
    int status;
    String message;
    Object data;

    public ResponseObject(int status, String message, Object data) {
        this.status = status;
        this.message = message;
        this.data = data;
    }

    public ResponseObject(HttpStatus httpStatus, String message, Object data) {
        this.status = httpStatus.value();
        this.message = message;
        this.data = data;
    }

    public ResponseObject(ErrorCode errorCode) {
        this.status = errorCode.getStatusCode().value();
        this.message = errorCode.getMessage();
        this.data = null;
    }
}
