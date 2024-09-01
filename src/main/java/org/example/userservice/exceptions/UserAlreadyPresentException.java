package org.example.userservice.exceptions;

public class UserAlreadyPresentException extends Exception {
    public UserAlreadyPresentException(String message) {
        super(message);
    }
}
