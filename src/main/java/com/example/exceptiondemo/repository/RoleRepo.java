package com.example.exceptiondemo.repository;

import com.example.exceptiondemo.enums.ERole;
import com.example.exceptiondemo.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepo extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleName(ERole roleName);
}
