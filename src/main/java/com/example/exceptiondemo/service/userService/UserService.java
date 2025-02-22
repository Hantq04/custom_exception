package com.example.exceptiondemo.service.userService;

import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.model.User;

import java.util.List;

public interface UserService {
    User insertUser(User user);

    void deleteUser(List<Integer> listUser);

    List<UserDTO> getUserList();

    User findByUserName(String userName);

    boolean existsByUserName(String userName);
}
