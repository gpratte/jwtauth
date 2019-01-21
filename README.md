# OVERVIEW

Create a Spring Boot server that 
1. Has an admin user
2. Allows new non-admin users to sign up. This endpoint does not require a token
3. Allows users to login. This endpoint does not require a token but returns a token
4. Allows the user to get his/her information. Requires token
5. Allows the admin user to get all users. Requires token
6. Exercise the endpoints via curl and/or Postman.

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
INSERT INTO user (id, username, password) VALUES (1, 'admin1', '$2a$10$qXQo4z4oXKPEKyYO7bAQmOQ9PhIcHK4LOo/L1U9j/xkLEmseLWECK');
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
curl -H "Content-Type: application/json" --user user:3bb88593-f38b-491d-9285-a7a081f2d157 -d '{
    "username": "Malcolm",
    "password": "Reynolds"
}' http://localhost:8080/users
```

##### Push the 04-security-basic-auth branch to github and merge it into master.


# GET one and GET many endpoints

##### Create a 05-endpoints-basic-auth branch from master.

### GET
Add the following endpoints to the controller

```
@GetMapping("/users")
public List<User> getAll() {
    return userService.get();
}

@GetMapping("/users/{id}")
public User getOne(@PathVariable Long id) {
    return userService.get(id);
}
```

Add the following methods to the service

```
public List<User> get() {
    return userRepository.findAll();
}

public User get(long id) {
    return userRepository.findById(id).get();
}
```

### curl

```
curl -H "Content-Type: application/json" --user user:46b2a3d6-9f11-42b2-a55c-70764f31ef3c http://localhost:8080/users

curl -H "Content-Type: application/json" --user user:46b2a3d6-9f11-42b2-a55c-70764f31ef3c http://localhost:8080/users/1
```

##### Push the 05-endpoints-basic-auth branch to github and merge it into master.


# JWT Authentication

##### Create a 06-jwt-auth branch from master.

There are a lot of moving parts for JWT authentication.

### JWT token library

Add the following dependency to the build.gradle file.

```
compile("io.jsonwebtoken:jjwt:0.9.0")
```

### Repository

Add the following to the UserRepository.

```
User findByUsername(String username);
```

### Encode Password

Change the create method in  the UserService to encode the password.

```
...

private final BCryptPasswordEncoder bCryptPasswordEncoder;

public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userRepository = userRepository;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
}

...

public User create(User user) {
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    return userRepository.save(user);
}
...
```

### UserDetailsService

The Javadoc for this interface says 

"Core interface which loads user-specific data."

The loadUserByUsername method will be called by the authentication plumbing.

In the service package create a UserDetailsServiceImpl class

```
package com.example.jwtauth.service;

import com.example.jwtauth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.example.jwtauth.model.User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), Collections.emptyList());
    }
}
```

### Password encoder

In the security package create a configuration class to declare the password encoder bean.

```
package com.example.jwtauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class JwtauthConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Constants 

In the security package create the SecurityConstants class

```
package com.example.jwtauth.security;

public class SecurityConstants {
    public static final String SIGNING_KEY = "5Lmr5JwJP4CSU";
    public static final String AUTHORITIES_KEY = "scopes";
    public static final long ACCESS_TOKEN_VALIDITY_SECONDS = 5*60*60;

    public static final String HEADER_STRING = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String SIGN_UP_URL = "/users";

}
```

### JWT token provider

This class does all the JWT specific functions like validating, get the name, get the password, create a token, ... .

In the security package create the JwtTokenProvider class

```
package com.example.jwtauth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.example.jwtauth.security.SecurityConstants.ACCESS_TOKEN_VALIDITY_SECONDS;
import static com.example.jwtauth.security.SecurityConstants.AUTHORITIES_KEY;
import static com.example.jwtauth.security.SecurityConstants.SIGNING_KEY;

@Component
public class JwtTokenProvider {
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(SIGNING_KEY)
            .parseClaimsJws(token)
            .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(Authentication authentication) {
        final String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));
        return Jwts.builder()
            .setSubject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS * 1000))
            .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    UsernamePasswordAuthenticationToken getAuthentication(final String token, final UserDetails userDetails) {

        final JwtParser jwtParser = Jwts.parser().setSigningKey(SIGNING_KEY);

        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

        final Claims claims = claimsJws.getBody();

        final Collection<? extends GrantedAuthority> authorities =
            Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
    }
}
```

### JWT Authentication Filter

This filter will extend the UsernamePasswordAuthenticationFilter class. By extending Spring's UsernamePasswordAuthenticationFilter Spring will place it in its proper place in the security chain.

This class extends the UsernamePasswordAuthenticationFilter and hence Spring will provide a login endpoint.

In the security package create the JWTAuthenticationFilter class

```
package com.example.jwtauth.security;

import com.example.jwtauth.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static com.example.jwtauth.security.SecurityConstants.HEADER_STRING;
import static com.example.jwtauth.security.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider JwtTokenProvider;


    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenProvider JwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.JwtTokenProvider = JwtTokenProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            User user = new ObjectMapper()
                .readValue(req.getInputStream(), User.class);

            return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword(),
                    new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        final String token = JwtTokenProvider.generateToken(auth);
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }
}
```

### JWT Authorization Filter

This filter will extend the BasicAuthenticationFilter class. 

The Javadoc for the BasicAuthenticationFilter says

"Processes a HTTP request's BASIC authorization headers, putting the result into the SecurityContextHolder."

In the security package create the JWTAuthorizationFilter class

```
package com.example.jwtauth.security;

import com.example.jwtauth.service.UserDetailsServiceImpl;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.jwtauth.security.SecurityConstants.HEADER_STRING;
import static com.example.jwtauth.security.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsServiceImpl userDetailsService;

    JWTAuthorizationFilter(AuthenticationManager authManager, JwtTokenProvider jwtTokenProvider, UserDetailsServiceImpl userDetailsService) {
        super(authManager);
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

        String username = null;
        String jwtToken = null;
        String header = request.getHeader(HEADER_STRING);
        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            jwtToken = header.replace(TOKEN_PREFIX,"");
            try {
                username = jwtTokenProvider.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                logger.error("an error occured during getting username from token", e);
            } catch (ExpiredJwtException e) {
                logger.warn("the token is expired and not valid anymore", e);
            } catch(SignatureException e){
                logger.error("Authentication Failed. Username or Password not valid.");
            }
        } else {
            logger.warn("couldn't find bearer string, will ignore the header");
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtTokenProvider.validateToken(jwtToken, userDetails)) {
                return jwtTokenProvider.getAuthentication(jwtToken, userDetails);
            }
        }

        return null;
    }

}
```

### Web Security

Update the WebSecurity class to use the new filters and service

```
package com.example.jwtauth.security;

import com.example.jwtauth.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static com.example.jwtauth.security.SecurityConstants.SIGN_UP_URL;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public WebSecurity(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
            .antMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtTokenProvider))
            .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtTokenProvider, userDetailsService))
            // this disables session creation on Spring Security
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}
```

##### See the curl commands to exercise the endpoints

##### Push the 06-jwt-auth branch to github and merge it into master.
