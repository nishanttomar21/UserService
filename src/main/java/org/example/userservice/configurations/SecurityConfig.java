// This class is used to disable the default security provided by "spring-boot-starter-security" dependency to allow API request from browser without authentication

package org.example.userservice.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        HttpSecurity csrf = http.authorizeRequests().anyRequest().permitAll()       // Permit all requests // So that the browser can access the APIs without authentication which is by default provided by "spring-boot-starter-security" dependency giving error - 401 Unauthorized
                                .and().csrf(AbstractHttpConfigurer::disable);

        return csrf.build();
    }
}
