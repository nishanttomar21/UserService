package org.example.userservice.services;

import org.example.userservice.dtos.LoginRequestDto;
import org.example.userservice.dtos.SignUpRequestDto;
import org.example.userservice.models.User;
import org.example.userservice.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;    // Dependency Injection
    private BCryptPasswordEncoder passwordEncoder;  // Password Encoder

    public AuthenticationService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {    // Constructor Injection (Repository Injection)
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Boolean signup(SignUpRequestDto signUpRequestDto) {
        // Get email from the request
        String email = signUpRequestDto.getEmail();

        // If user already exists, return false
        if (userRepository.findByEmail(email).isPresent()) {
            return false;
        }

        // Encode the password for security
        String rawPassword = signUpRequestDto.getPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword);

        // DTO --> Model (Data conversion)
        User newUser = SignUpRequestDto.toUser(email, encodedPassword);

        // If user does not exist, create a new user and return true
        userRepository.save(newUser);

        return true;
    }

    public Boolean login(LoginRequestDto loginRequestDto) {
        // DTO --> Model (Data conversion)
        User user = LoginRequestDto.toUser(loginRequestDto);
        String email = user.getEmail();
        String password = user.getPassword();

        Optional<User> existingUser = userRepository.findByEmail(email);

        // If user does not exist, return false
        if (existingUser.isEmpty()) {
            return false;
        }

        // Check if the password matches
        Boolean match = passwordEncoder.matches(password, existingUser.get().getPassword());

        if (!match) {
            return false;
        }

        return true;
    }
}
