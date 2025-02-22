package com.example.exceptiondemo.dto;

import com.example.exceptiondemo.groupValidate.InsertUser;
import com.example.exceptiondemo.groupValidate.LoginUser;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserDTO {
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    Integer userId;

    @NotBlank(message = "NOT_BLANK", groups = {InsertUser.class, LoginUser.class})
    @Size(min = 4, max = 20, message = "INVALID_USERNAME", groups = {InsertUser.class, LoginUser.class})
    String userName;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotBlank(message = "NOT_BLANK", groups = {InsertUser.class, LoginUser.class})
    @Pattern(
            regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,20}$",
            message = "INVALID_PASSWORD",
            groups = {InsertUser.class, LoginUser.class}
    )
    String password;

    @NotEmpty(message = "NOT_EMPTY", groups = {InsertUser.class})
    Set<String> listRoles;
}
