package org.example.userservice.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class MyBeans {

    @Bean
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {       // This method is used to create a BCryptPasswordEncoder bean
        return new BCryptPasswordEncoder();
    }
}
