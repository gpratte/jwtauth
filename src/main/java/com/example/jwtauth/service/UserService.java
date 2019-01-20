package com.example.jwtauth.service;

import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User create(User user) {
        // TODO encrypt password
        return userRepository.save(user);
    }

    public List<User> get() {
        return userRepository.findAll();
    }

    public User get(long id) {
        return userRepository.findById(id).get();
    }

}
