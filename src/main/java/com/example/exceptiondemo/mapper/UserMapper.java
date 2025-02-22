package com.example.exceptiondemo.mapper;

import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.exception.ErrorCode;
import com.example.exceptiondemo.model.Role;
import com.example.exceptiondemo.model.User;
import com.example.exceptiondemo.enums.ERole;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "userId", ignore = true)
    @Mapping(source = "listRoles", target = "listRoles", qualifiedByName = "mapRolesToEntities")
    User toUser(UserDTO userDTO);

    @Mapping(source = "listRoles", target = "listRoles", qualifiedByName = "mapRolesToStrings")
    UserDTO toUserDTO(User user);

    @Named("mapRolesToEntities")
    default Set<Role> mapRolesToEntities(Set<String> roleNames) {
        if (roleNames == null) return null;
        return roleNames.stream()
                .map(roleName -> {
                    Role role = new Role();
                    String formattedRole = roleName.trim().toUpperCase();
                    if (!formattedRole.startsWith("ROLE_")) {
                        formattedRole = "ROLE_" + formattedRole;
                    }
                    try {
                        role.setRoleName(ERole.valueOf(formattedRole)); // Chuyển String thành ERole
                    } catch (IllegalArgumentException e) {
                        throw new AppException(ErrorCode.INVALID_ROLE); // Báo lỗi dễ hiểu hơn
                    }
                    return role;
                })
                .collect(Collectors.toSet());
    }

    @Named("mapRolesToStrings")
    default Set<String> mapRolesToStrings(Set<Role> roles) {
        if (roles == null) return null;
        return roles.stream()
                .map(role -> role.getRoleName().name()) // Chuyển ERole thành String
                .collect(Collectors.toSet());
    }
}
