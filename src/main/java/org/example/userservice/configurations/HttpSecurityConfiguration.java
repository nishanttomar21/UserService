/*
 This class is used to disable the default security provided by "spring-boot-starter-security" dependency to allow API request from browser without authentication
 SecurityFilterChain - It's responsible for defining the security rules and filters that govern how HTTP requests are handled and authenticated. It offers a flexible way to customize security behavior by adding, removing, or modifying filters and their configurations.

 securityFilterChain():
     1. The method takes an HttpSecurity object as a parameter. HttpSecurity is used to configure web-based security for specific http requests.
     2. http.authorizeRequests() starts configuring authorization rules.
     3. .anyRequest().permitAll() sets a rule that allows any request to be permitted without authentication. This means all endpoints are accessible to everyone.
     4. .and() is used to chain another configuration.
     5. .csrf(AbstractHttpConfigurer::disable) disables CSRF (Cross-Site Request Forgery) protection. This is done by passing a method reference to the disable() method of AbstractHttpConfigurer.
     6. The configured HttpSecurity object is then built using .build() to create the SecurityFilterChain.
     7. Finally, the method returns this SecurityFilterChain.

     This configuration is very permissive and would typically be used in development environments or for public APIs that don't require authentication. In a production environment, you'd usually want more restrictive security settings.
     It's worth noting that disabling CSRF protection can be a security risk if your application handles user-specific actions or authenticated sessions. You should only disable CSRF if you have a specific reason to do so and understand the security implications.
*/

package org.example.userservice.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class HttpSecurityConfiguration {

    @Bean
    // It permits all requests to all endpoints without requiring authentication and it disables CSRF protection.
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        HttpSecurity csrf = http.authorizeRequests().anyRequest().permitAll()       // Permit all requests // So that the browser can access the APIs without authentication which is by default provided by "spring-boot-starter-security" dependency giving error - 401 Unauthorized
                                .and().csrf(AbstractHttpConfigurer::disable);

        return csrf.build();
    }
}
