package org.example.userservice.dtos;

import lombok.Getter;
import lombok.Setter;
import org.example.userservice.models.User;

@Getter
@Setter
public class SignUpRequestDto {

    private String email;
    private String password;

    // This method is used to convert a SignUpRequestDto(DTO) object to a User(Model) object
    public static User toUser(SignUpRequestDto signUpRequestDto) {
        User user = new User();

        user.setEmail(signUpRequestDto.getEmail());
        user.setPassword(signUpRequestDto.getPassword());

        return user;
    }
}
