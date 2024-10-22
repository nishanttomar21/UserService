// ResponseEntity - The ResponseEntity class in Spring is a powerful way to represent the entire HTTP response, including the status code, headers, and body. It's often used in controllers to return responses from RESTful APIs. Using ResponseEntity in Spring Boot is optional but highly recommended, especially when you want to have fine-grained control over your HTTP responses
// [Important] Run Service Discover codebase before running this User Service

package org.example.userservice.controllers;

import org.example.userservice.dtos.*;
import org.example.userservice.exceptions.UserAlreadyPresentException;
import org.example.userservice.services.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;  // Dependency Injection

    public AuthenticationController(AuthenticationService authenticationService) {  // Constructor Injection (Service Injection)
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponseDto> signup(@RequestBody SignUpRequestDto signUpRequestDto) throws UserAlreadyPresentException {
        SignUpResponseDto response = new SignUpResponseDto();
        authenticationService.signup(signUpRequestDto);

        try {
            if (authenticationService.signup(signUpRequestDto)) {
                response.setRequestStatus(RequestStatus.SUCCESS);
                response.setMessage("User signed up successfully!");
            } else {
                response.setRequestStatus(RequestStatus.FAILURE);
                response.setMessage("Failure during signup!");
            }

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.setRequestStatus(RequestStatus.FAILURE);
            response.setMessage(e.getMessage());

            return new ResponseEntity<>(response, HttpStatus.CONFLICT);
        }
    }

    @GetMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        try {
            String token = authenticationService.login(loginRequestDto);

            LoginResponseDto loginDto = new LoginResponseDto();
            loginDto.setRequestStatus(RequestStatus.SUCCESS);
            loginDto.setMessage("User logged in successfully!");

            MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();    // MultiValueMap to store multiple values for a single key, LinkedMultiValueMap to maintain the order of insertion
            headers.add("AUTH_TOKEN", token);

            ResponseEntity<LoginResponseDto> response = new ResponseEntity<>(loginDto, headers , HttpStatus.OK);

            return response;
        } catch (Exception e) {
            LoginResponseDto loginDto = new LoginResponseDto();
            loginDto.setRequestStatus(RequestStatus.FAILURE);
            loginDto.setMessage(e.getMessage());

            ResponseEntity<LoginResponseDto> response = new ResponseEntity<>(loginDto, null , HttpStatus.BAD_REQUEST);

            return response;
        }
    }

    @GetMapping("/validate")
    public Boolean validate(@RequestParam("token") String token) {
        return authenticationService.validate(token);
    }
}
