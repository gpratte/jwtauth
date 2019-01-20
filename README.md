# OVERVIEW

Create a Spring Boot server that 
1. Has an admin user
2. Allows new non-admin users to sign up. This endpoint does not require a token
3. Allows users to login. This endpoint does not require a token but returns a token
4. Allows the user to get his/her information. Requires token
5. Allows the admin user to get all users. Requires token
6. Allows a user to change his/her password. Requires token
7. Allows the admin user to change a user's password. Requires token
8. Exercise the endpoints via curl and/or Postman.

# SETUP

Create a Spring Boot project using Spring Initialzr

https://start.spring.io/

Choose Gradle for the build tool.

Chose the following dependencies:
* Web
* JPA
* H2
* Lombok

Change the Artifact to "jwtauth".

Generate the project, unzip it and load it up in your IDE. If you are using IntelliJ then remember to install the Lombok plugin and change the settings to enable annotations. 

Run the test to make sure everything is working.

# GIT
As per usual I will build up this application on git branches. 

I created a github repository at https://github.com/gpratte/jwtauth.git

I pushed the code from the SETUP section above to the master branch and then pushed it to a 01-setup branch.



# ADMIN USER

##### Create a 02-admin-user branch from master.

### User database table
In the src/main/resources folder create a data.sql file. Spring Boot will see the H2 dependency and will execute this file on start up.

```
drop table if exists user;
create table user (id int not null auto_increment, username varchar(255), password varchar(255), primary key (id));
-- password is password1
INSERT INTO user (id, username, password) VALUES (1, 'admin1', '$2a$04$Ye7/lJoJin6.m9sOJZ9ujeTgHEVM4VXgI2Ingpsnf9gXyXEXf/IlW');
```

### User model
Create a com.example.jwtauth.model package.

Create a User class for JPA.

```
package com.example.jwtauth.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
}
```

### User repository
Create a com.example.jwtauth.repository package.

Create a UserRepository interface

```
package com.example.jwtauth.repository;

import com.example.jwtauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {}
```

### Command line running in main
Add a command line running to main to print out the users.

```
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
```

##### Push the 02-admin-user branch to github and merge it into master.


# NEW USER

##### Create a 03-new-user branch from master.

### User service
Create a com.example.jwtauth.service package.

Create a UserService class

```
package com.example.jwtauth.service;

import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.UserRepository;
import org.springframework.stereotype.Service;

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
}

```

### User controller
Create a com.example.jwtauth.controller package.

Create a UserController class

```
package com.example.jwtauth.controller;

import com.example.jwtauth.model.User;
import com.example.jwtauth.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
}
```

### curl
`curl -H "Content-Type: application/json" -X POST -d '{
    "username": "Malcolm",
    "password": "Reynolds"
}' http://localhost:8080/users`

See the curl-and-postman folder for this curl and a postman file to import into postman.


##### Push the 03-new-user branch to github and merge it into master.


# Basic Authentication

##### Create a 04-security-basic-auth branch from master.

### spring security

Add the spring security dependency to the build.gradle file.

`implementation 'org.springframework.boot:spring-boot-starter-security'`

Run the curl command to try to create a new user and you will see that the http status returned is a 401 Unauthorized. You will probably need to add the -v option to the command to see the return status.

```
curl -v -H "Content-Type: application/json" -X POST -d '{
    "username": "Malcolm",
    "password": "Reynolds"
}' http://localhost:8080/users
```

### web security

Create a com.example.jwtauth.security package.

Create a WebSecurity class

```
package com.example.jwtauth.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
            .anyRequest().authenticated()
            .and().httpBasic();
    }
}
```

This sets the authentication to be basic (and it does other stuff for you to figure out).

### basic auth

In the output logging when server starts up you will see a number something like this

Using generated security password: 3bb88593-f38b-491d-9285-a7a081f2d157

Change the curl to pass the default user name "user" and the password. In this case the curl would be

```
curl -H "Content-Type: application/json" --user user:62c26eb3-f88b-42a6-88aa-b24b56ade6ce -d '{
    "username": "Malcolm",
    "password": "Reynolds"
}' http://localhost:8080/users
```

##### Push the 04-security-basic-auth branch to github and merge it into master.
