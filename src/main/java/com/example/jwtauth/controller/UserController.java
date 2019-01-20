package com.example.jwtauth.controller;

import com.example.jwtauth.model.User;
import com.example.jwtauth.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userService.create(user);
    }

    @GetMapping("/users")
    public List<User> getAll() {
        return userService.get();
    }

    @GetMapping("/users/{id}")
    public User getOne(@PathVariable Long id) {
        return userService.get(id);
    }

}
