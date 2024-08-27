package org.example.userservice.controllers;

import org.example.userservice.dtos.LoginRequestDto;
import org.example.userservice.dtos.SignUpRequestDto;
import org.example.userservice.services.AuthenticationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;  // Dependency Injection

    public AuthenticationController(AuthenticationService authenticationService) {  // Constructor Injection (Service Injection)
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public Boolean signup(@RequestBody SignUpRequestDto signUpRequestDto) {
        Boolean response = authenticationService.signup(signUpRequestDto);

        return response;
    }

    @GetMapping("/login")
    public Boolean login(@RequestBody LoginRequestDto loginRequestDto) {
        Boolean response = authenticationService.login(loginRequestDto);

        return response;
    }
}
