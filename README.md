# Java Security Day 2 Workshop

## Learning Objectives
- Use a Bearer Token/JWT to secure an API

## Instructions

1. Fork this repository
2. Clone your fork to your machine
3. Open the project in IntelliJ

## Some Theory

A common way of securing a web application is to use a Bearer token that the user obtains by logging in. Anytime authentication is then required the user submits this token as part of the Http Request, it is checked and if valid then the user is allowed to complete their process, if it isn't then an Unauthorised response is returned. The core of the process works like this:

1. A user enters their login details into a form
2. The client sends the credentials to a server in the body of a request to an API
3. The server checks the credentials are correct
4. The server creates an access token for the user and sends it back to the client
5. The client saves the token and sends it in a request header when the user tries to access protected areas of the app

We can visualise the process like this:

![A user logs in to an app](./assets/Auth_Flow.png)

## What's a Token?

> Think of a token like an employee ID badge; you can't enter the secure areas of your employer's building without one! The company verify that you are who you say you are when they hire you, and then they give you an ID badge so you can access employee-only rooms in the building.

In this analogy, verifying you are who you say you are symbolises entering a username and password into a login form. The ID badge granted to you is the token; only you have this token, and you show it to the server every time you want to make a request to a protected resource.

One of the most common types of tokens are called JSON Web Token's, a.k.a JWT's.

A JWT is comprised of 2 separate pieces of JSON and a signature hash, each of them encoded and placed into a string separated by dots.

The final token will have a structure that looks like xxxxx.yyyyy.zzzzz

The three pieces are:

1. Header (xxxxx)
2. Payload (yyyyy)
3. Signature (zzzzz)

## Building Our Secure App

We'll start off with a full version of the Books endpoints we used yesterday (but this time including the `POST`, `PUT` and `DELETE` ones too). The code for this is already included in the aprropriate folders in the project.

## Setting up `application.yml` and `build.gradle`

Add the usual connection details to your `application.yml` file, we'll add some extra configuration there shortly. Then open `build.gradle` and add the following code to it.

```groovy
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.1.5'
	id 'io.spring.dependency-management' version '1.1.3'
}

group = 'com.booleanuk'
version = '0.0.1-SNAPSHOT'

java {
	sourceCompatibility = '17'
}

configurations {
	compileOnly {
		extendsFrom annotationProcessor
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
	implementation 'org.springframework.boot:spring-boot-starter-security'
	implementation 'org.springframework.boot:spring-boot-starter-web'
	implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
	implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
	runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'

	implementation 'org.springframework.boot:spring-boot-starter-thymeleaf'
	implementation 'org.thymeleaf.extras:thymeleaf-extras-springsecurity6'
	compileOnly 'org.projectlombok:lombok'
	developmentOnly 'org.springframework.boot:spring-boot-devtools'
	runtimeOnly 'org.postgresql:postgresql'
	annotationProcessor 'org.projectlombok:lombok'
	testImplementation 'org.springframework.boot:spring-boot-starter-test'
	testImplementation 'org.springframework.security:spring-security-test'

	implementation 'jakarta.validation:jakarta.validation-api:3.0.2'
}

tasks.named('bootBuildImage') {
	builder = 'paketobuildpacks/builder-jammy-base:latest'
}

tasks.named('test') {
	useJUnitPlatform()
}
```

This is very similar to yesterday's code but with a few additional libraries to help handle JWTs.

Now go back to your `application.yml` file and at the bottom add the following:

```yaml
booleanuk:
  app:
    jwtSecret: ===============================BooleanUK=Spring==============================================
    jwtExpirationMs: 86400000
```

The `jwtSecret` entry can be any text you want and is part of the process for encrypting and decrypting the JWTs, one thing to be aware of is that if the string used is too short then you will get error messages and will not be able to login. The `jwtExpiration` entry sets the time in Milliseconds until the token expires and the user has to login again (86400000ms is 24 hours).

## Adding Models for the User, Role and ERole

The ERole class is going to contain the three possible roles a user can have, in the form of an Enumeration, which we'll then use elsewhere in the code. In the `models` package click on New -> Java Class and add an `Enum` called `ERole` (the E in the name is to tell us this is an Enum). Then add the following code to it:

```java
package com.booleanuk.library.models;

public enum ERole {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
```

Then we want to add code for our `Role` and `User` model classes to the same package so create the `Role` one first and add this:

```java
package com.booleanuk.library.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    public Role(ERole name) {
        this.name = name;
    }
}
```

then do the same for `User` and add this:

```java
package com.booleanuk.library.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@NoArgsConstructor
@Data
@Entity
@Table(name = "users",
        uniqueConstraints = {
            @UniqueConstraint(columnNames = "username"),
            @UniqueConstraint(columnNames = "email")
        })
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @NotBlank
    @Size(max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 120)
    private String password;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}
```

We also have a Many-to-Many relationship in here, which will create a separate joining table in the database and link the user's id to the role's id as user's will be able to have multiple roles.

## Add a User and Role Repository

We also need repositories for the User and the Role so add a `UserRepository` interface class and a `RoleRepository` interface class in the normal place and add the code as follows:

```java
package com.booleanuk.library.repository;

import com.booleanuk.library.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
```

```java
package com.booleanuk.library.repository;

import com.booleanuk.library.models.ERole;
import com.booleanuk.library.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
```

Both the `User` and the `Role` need some extra methods so we add those here and Spring does the rest to enable them.

## Adding Request Classes to Use when Logging In or Signing Up

We are going to use an `AuthController` class which will handle the endpoints for logging and signing in, but they will both need some classes to handle the data coming from the `POST` request as Request Body Variables, so we can create those now. Find the `payload` package, it already contains the `response` package add a new package in `payload` called `request` and then create two new Java classes in there called `LoginRequest` and `SignupRequest` these classes just need the following:

```java
package com.booleanuk.library.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;
}
```

and

```java
package com.booleanuk.library.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    private Set<String> role;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
}
```

When we make the `POST` requests the JSON which comes will map into these classes.

## Responses 

When we Signup successfully we'll need to receive a message back from the server to tell us if we were successful and if we Login successfully we'll need to get a JSON object back which includes the bearer token and other data, we'll add some classes to the `response` package now which will map across to these objects automatically.

Add a `MessageResponse` class in the `response` package with the following code in it:

```java
package com.booleanuk.library.payload.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MessageResponse {
    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }
}
```

plus add a `JwtResponse` class and put this code in it:

```java
package com.booleanuk.library.payload.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private int id;
    private String username;
    private String email;
    private List<String> roles;

    public JwtResponse(String accessToken, int id, String username, String email, List<String> roles) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public String getAccessToken() {
        return this.getToken();
    }

    public void setAccessToken(String accessToken) {
        this.setToken(accessToken);
    }

    public String getTokenType() {
        return this.getType();
    }

    public void setTokenType(String tokenType) {
        this.setType(tokenType);
    }
}
```

## Adding Some Helper Classes

We need to make a new package inside the `library` package called `security` in there we're going to have two more packages one called `services` and the other called `jwt` which are going to contain some Helper classes to enable us to build our application. Inside the `jwt` package add a new class called `AuthEntryPointJwt` and add the following code to it:

```java
package com.booleanuk.library.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
    }
}
```

This is the code which gets run whenever someone unauthenticated tries to access an endpoint that requires authentication. Next add an `AuthTokenFilter` class to the `jwt` package with the following code in it:

```java
package com.booleanuk.library.security.jwt;

import com.booleanuk.library.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}
```

This class checks the user has supplied a valid token and that they have the correct roles to enable them to complete the process they are trying to run. It either authenticates them or returns an error. Finally add a `JwtUtils` class to the package, this contains various methods to do with handling and building the `JWT` token. Add the following code to it:

```java
package com.booleanuk.library.security.jwt;

import com.booleanuk.library.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${booleanuk.app.jwtSecret}")
    private String jwtSecret;

    @Value("${booleanuk.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() +jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
```

This is where an error will be triggered if the jwtSecret you added to the `application.yml` file is not long enough. Now move into the `services` package and add a `UserDetailsImpl` class with the following code in it:

```java
package com.booleanuk.library.security.services;


import com.booleanuk.library.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Getter
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private int id;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(int id, String username, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}
```

This class is used to convert the raw user object into something that can interact with the other parts of the API. Then add a `UserDetailsServiceImpl` class too, with the following code:

```java
package com.booleanuk.library.security.services;

import com.booleanuk.library.models.User;
import com.booleanuk.library.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("User not found with username " + username));
        return UserDetailsImpl.build(user);
    }
}
```

This part overrides some built in code to handle what happens when the username is not recognised.

## Adding our SecurityConfiguration File

Next we're going add our SecurityConfiguration file inside the `security` package. This time we'll call the class `WebSecurityConfig` create it and add the following code to it:

```java
package com.booleanuk.library.security;

import com.booleanuk.library.security.jwt.AuthEntryPointJwt;
import com.booleanuk.library.security.jwt.AuthTokenFilter;
import com.booleanuk.library.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrf) -> csrf.disable())
                .exceptionHandling((exception) -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/books", "/books/**").authenticated()
                );
        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

This is similar to what we did previously, but has some methods to set up various parts of the authentication procedure first, then we build our `SecurityFilterChain` as we did before, but this time including our `/auth` endpoint so that we can login via there.

## Add a Controller for Logging in and Signing Up

Find the `controllers` package and add an `AuthController` class to it with the following code in it:

```java
package com.booleanuk.library.controllers;

import com.booleanuk.library.models.ERole;
import com.booleanuk.library.models.Role;
import com.booleanuk.library.models.User;
import com.booleanuk.library.payload.request.LoginRequest;
import com.booleanuk.library.payload.request.SignupRequest;
import com.booleanuk.library.payload.response.JwtResponse;
import com.booleanuk.library.payload.response.MessageResponse;
import com.booleanuk.library.repository.RoleRepository;
import com.booleanuk.library.repository.UserRepository;
import com.booleanuk.library.security.jwt.JwtUtils;
import com.booleanuk.library.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // If using a salt for password use it here
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map((item) -> item.getAuthority())
                .collect(Collectors.toList());
        return ResponseEntity
                .ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }
        // Create a new user add salt here if using one
        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach((role) -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok((new MessageResponse("User registered successfully")));
    }
}
```

The class contains various autowired components so that we don't need to explicitly instantiate them, then we have our `signin` method which expects a `POST` request containing a JSON object that has a `username` and a `password`, these are passed around to ensure they're valid and returns an object including the token which can then be used elsewhere to access the other endpoints of our application. The `signin` endpoint works in a similar fashion except it generates a new entry in the User table with the correct entries.

## Add Roles to the Database

* Run the application as normal.
* Fix all of the bugs you have deliberately added to your code.
* Then visit the database using TablePlus or something similar.
* Before you can proceed you will need to add the required roles to the `roles` table otherwise everything will fail.
* Run the following SQL command to add the correct data:

```SQL
INSERT INTO 
	roles(name) 
VALUES
	('ROLE_USER'),
	('ROLE_MODERATOR'),
	('ROLE_ADMIN');
```

you can add some books at this point too so that there is data to interact with if you wish. Now visit the [http://localhost:4000/auth/signup](http://localhost:4000/auth/signup) endpoint using a `POST` request in Insomnia and passing in a JSON object similar to this:

```json
{
	"username": "dave",
	"email": "dave@email.com",
	"password": "password",
	"role": ["mod", "user"]
}
```

If everything has been successfully completed then this should create a new user in the database. Notice that the password column does not contain the password in plain text (see the next section). Now try logging in using the same credentials, this time make a `POST` request to [http://localhost:4000/auth/signin](http://localhost:4000/auth/signin) and a JSON object containing:

```json
{
	"username": "dave",
	"password": "password"
}
```

or whatever information you signed up using. You should get back something that looks like this:

```json
{
	"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXZlIiwiaWF0IjoxNzAwMjIxMjA4LCJleHAiOjE3MDAzMDc2MDh9.Bc3RAZ8DbVIkRz-lC1NeHZxe2TGMIEa7eJFtq0aomag",
	"type": "Bearer",
	"id": 1,
	"username": "dave",
	"email": "dave@email.com",
	"roles": [
		"ROLE_USER",
		"ROLE_MODERATOR"
	],
	"accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXZlIiwiaWF0IjoxNzAwMjIxMjA4LCJleHAiOjE3MDAzMDc2MDh9.Bc3RAZ8DbVIkRz-lC1NeHZxe2TGMIEa7eJFtq0aomag",
	"tokenType": "Bearer"
}
```

Copy the text that is in the `token` or `accessToken` fields. In Insomnia open up a Get Request to the Get all Books endpoint: [http://localhost:4000/books](http://localhost:4000/books) , try and access it you should be denied. So go to the `Authentication` tab and choose Bearer. Paste the token string into the TOKEN part and add the word Bearer to the prefix part then try making the request again, this time you should succeed.

## Encryption

We're using the BCrypt encryption system to encrypt and decrypt our passwords. Let's have a play with how it works. Add a new package called `CommandLine` and add a new Java class to it called `ManualEncryption` with the following code in it:

```java
package com.booleanuk.commandline;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class ManualEncryption {
    public static void main(String[] args) {
        String password = "password";
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String encoded = encoder.encode(password);
        System.out.println(encoded);
    }
}
```

Run this file, make a note of the output. Now run it again, what do you notice?

You may think that as the password is being encode differently each time it isn't much use, but there is more going on that meets the eye. Add a line that contains the following to the end of the method and run it again:

```java
System.out.println(encoder.matches("password", encoded));
```

This should output true if the encoded password originally had the text "password" in it and false if not. We are using this feature in the background of our application to ensure that the encrypted password matches the one that has been used to log in.

Change the code to the following and play with it some more so that you have a good feel for it:

```java
package com.booleanuk.commandline;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class ManualEncryption {
    public static void main(String[] args) {
        String password = "password";
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String encoded = encoder.encode(password);
        System.out.println(encoded);

        String password2 = "password";
        String alsoEncoded = encoder.encode(password2);
        System.out.println(alsoEncoded);

        System.out.println(encoder.matches("password", encoded));
        System.out.println(encoder.matches("password", alsoEncoded));
    }
}
```

## Exercises

* What do we mean by the term `Salt` in the context of passwords?
* Why is it important? 
* How could we add it to our code?
