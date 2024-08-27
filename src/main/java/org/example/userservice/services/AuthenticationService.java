package org.example.userservice.services;

import org.example.userservice.dtos.LoginRequestDto;
import org.example.userservice.dtos.SignUpRequestDto;
import org.example.userservice.models.User;
import org.example.userservice.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;    // Dependency Injection

    public AuthenticationService(UserRepository userRepository) {    // Constructor Injection (Repository Injection)
        this.userRepository = userRepository;
    }

    public Boolean signup(SignUpRequestDto signUpRequestDto) {
        // DTO --> Model (Data conversion)
        User newUser = SignUpRequestDto.toUser(signUpRequestDto);
        String email = newUser.getEmail();
        String password = newUser.getPassword();

        // If user already exists, return false
        if (userRepository.findByEmail(email).isPresent()) {
            return false;
        }

        // If user does not exist, create a new user and return true
        userRepository.save(newUser);

        return true;
    }

    public Boolean login(LoginRequestDto loginRequestDto) {
        // DTO --> Model (Data conversion)
        User user = LoginRequestDto.toUser(loginRequestDto);
        String email = user.getEmail();
        String password = user.getPassword();

        // If user does not exist, return false
        if (userRepository.findByEmail(email).isEmpty()) {
            return false;
        }

        // If user exists, check if the password is correct
        User existingUser = userRepository.findByEmail(email).get();

        if (!existingUser.getPassword().equals(password)) {
            return false;
        }

        return true;
    }
}
