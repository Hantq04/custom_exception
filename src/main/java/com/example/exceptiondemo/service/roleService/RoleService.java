package com.example.exceptiondemo.service.roleService;

import com.example.exceptiondemo.enums.ERole;
import com.example.exceptiondemo.model.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findByRoleName(ERole roleName);
}
