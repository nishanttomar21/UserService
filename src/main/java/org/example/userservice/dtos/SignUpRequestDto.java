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
    public static User toUser(String email, String password) {
        User user = new User();

        user.setEmail(email);
        user.setPassword(password);

        return user;
    }
}
