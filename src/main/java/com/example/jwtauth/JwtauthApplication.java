package com.example.jwtauth;

import com.example.jwtauth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtauthApplication implements CommandLineRunner {

	@Autowired
	UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(JwtauthApplication.class, args);
	}

	@Override
	public void run(String... args) {
		System.out.println(">>>> Users");
		userRepository.findAll().forEach(System.out::println);
	}
}

