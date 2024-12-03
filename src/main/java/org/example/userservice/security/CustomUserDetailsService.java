// This service plays a crucial role in the authentication process. When a user attempts to log in, Spring Security will use this service to load the user's details from the database. These details are then used to verify the provided credentials and, if successful, create an authenticated session for the user.

package org.example.userservice.security;

import org.example.userservice.models.User;
import org.example.userservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(username);
        if(userOptional.isEmpty()) throw new UsernameNotFoundException("user not found");

        return new CustomUserDetails(userOptional.get());
    }
}