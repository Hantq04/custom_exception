package com.example.exceptiondemo.service.userService;

import com.example.exceptiondemo.dto.UserDTO;
import com.example.exceptiondemo.exception.AppException;
import com.example.exceptiondemo.exception.ErrorCode;
import com.example.exceptiondemo.mapper.UserMapper;
import com.example.exceptiondemo.model.User;
import com.example.exceptiondemo.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepo userRepo;
    public final UserMapper userMapper;

    @Override
    public User insertUser(User user) {
        if (userRepo.existsByUserName(user.getUserName())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }
        return userRepo.save(user);
    }

    @Override
    public void deleteUser(List<Integer> listUser) {
        listUser.forEach(user -> {
            User users = userRepo.findById(user)
                    .orElseThrow(() -> new AppException(ErrorCode.NOT_FOUND));
            userRepo.delete(users);
        });
    }

    @Override
    public List<UserDTO> getUserList() {
        List<User> getUserList = userRepo.findAll();
        return getUserList.stream()
                .map(userMapper::toUserDTO)
                .collect(Collectors.toList());
    }

    @Override
    public User findByUserName(String userName) {
        return userRepo.findByUserName(userName);
    }

    @Override
    public boolean existsByUserName(String userName) {
        return userRepo.existsByUserName(userName);
    }
}
