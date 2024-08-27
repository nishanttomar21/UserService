package org.example.userservice.dtos;

import lombok.Getter;
import lombok.Setter;
import org.example.userservice.models.User;

@Getter
@Setter
public class LoginRequestDto {
    private String email;
    private String password;

    // This method is used to convert a LoginRequestDto(DTO) object to a User(Model) object
    public static User toUser(LoginRequestDto loginRequestDto) {
        User user = new User();

        user.setEmail(loginRequestDto.getEmail());
        user.setPassword(loginRequestDto.getPassword());

        return user;
    }
}
