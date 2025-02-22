package com.example.exceptiondemo.service.roleService;

import com.example.exceptiondemo.enums.ERole;
import com.example.exceptiondemo.model.Role;
import com.example.exceptiondemo.repository.RoleRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService{
    private final RoleRepo roleRepo;

    @Override
    public Optional<Role> findByRoleName(ERole roleName) {
        return roleRepo.findByRoleName(roleName);
    }
}
