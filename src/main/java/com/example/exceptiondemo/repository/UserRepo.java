package com.example.exceptiondemo.repository;

import com.example.exceptiondemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User, Integer> {
    User findByUserName(String userName);

    boolean existsByUserName(String userName);
}
