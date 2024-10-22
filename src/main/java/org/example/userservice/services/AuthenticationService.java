// hmacShaKeyFor() is a static method in the Keys class that generates a secret key from the given byte array. The byte array is the secret key that is used to sign the JWT. The key is generated using the HMAC algorithm with SHA-256 as the hash function. The key is then used to sign the JWT.
// We can validate JWT without any storage by using the Jwts.parser().verifyWith(key).build().parseSignedClaims(token) method. This method parses the JWT token and returns the claims stored in the token. If the token is invalid or has expired, it will throw an exception.
// ObjectMapper - A fast JSON parser and generator for Java. It can be used to convert Java objects to JSON and vice versa.
// TODO: Get the claims from the token (check that user is only allowed to have 2 active sessions at a time)

package org.example.userservice.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.userservice.client.KafkaProducerClient;
import org.example.userservice.dtos.EmailDto;
import org.example.userservice.dtos.LoginRequestDto;
import org.example.userservice.dtos.SignUpRequestDto;
import org.example.userservice.exceptions.UserAlreadyPresentException;
import org.example.userservice.exceptions.UserNotFoundException;
import org.example.userservice.exceptions.WrongPasswordException;
import org.example.userservice.models.Session;
import org.example.userservice.models.User;
import org.example.userservice.repository.SessionRepository;
import org.example.userservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;    // Dependency Injection

    @Autowired
    private SessionRepository sessionRepository;  // Dependency Injection

    private BCryptPasswordEncoder passwordEncoder;  // Password Encoder

    @Autowired
    private ObjectMapper objectMapper;

    // private SecretKey key = Jwts.SIG.HS256.key().build();    // This key changes each time you restart the server
    private SecretKey key = Keys.hmacShaKeyFor("nishantisveryveryveryveryveryveryverycool".getBytes(StandardCharsets.UTF_8));     // This key is constant key

    @Autowired
    private KafkaProducerClient kafkaProducerClient;


    // Constructor Injection
    public AuthenticationService(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public Boolean signup(SignUpRequestDto signUpRequestDto) throws UserAlreadyPresentException {
        // Get email from the request
        String email = signUpRequestDto.getEmail();

        // If user already exists, return false
        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyPresentException("User with email: " + email + " already exists!");    // Custom Exception
        }

        // Encode the password for security
        String rawPassword = signUpRequestDto.getPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword);   // bCryptPasswordEncoder.encode is a method in the BCryptPasswordEncoder class that takes a raw password as input and encodes it using the BCrypt hashing algorithm. The encoded password is then stored in the database. When a user logs in, the entered password is hashed using the same algorithm, and the hashed value is compared with the stored hashed password to verify the user's identity.

        // DTO --> Model (Data conversion)
        User newUser = SignUpRequestDto.toUser(email, encodedPassword);

        // If user does not exist, create a new user and return true
        userRepository.save(newUser);

        // Kafka: Send message into kafka message queue for welcome email to be sent to the new user
        try {
            EmailDto emailDto = new EmailDto();
            emailDto.setTo(email);
            emailDto.setSubject("Welcome to Scaler");
            emailDto.setBody("Have a pleasant learning experience.");
            emailDto.setFrom("nishanttomar211@gmail.com");

            kafkaProducerClient.sendMessage("user_signedup", objectMapper.writeValueAsString(emailDto));
        } catch (JsonProcessingException exception) {
            throw new RuntimeException(exception.getMessage());
        }

        return true;
    }

    public String login(LoginRequestDto loginRequestDto) throws UserNotFoundException, WrongPasswordException {
        // DTO --> Model (Data conversion)
        User user = LoginRequestDto.toUser(loginRequestDto);
        String email = user.getEmail();
        String password = user.getPassword();

        Optional<User> existingUser = userRepository.findByEmail(email);

        // If user does not exist, return false
        if (existingUser.isEmpty()) {
            throw new UserNotFoundException("User with email: " + email + " does not exist!");    // Custom Exception
        }

        // Check if the password matches
        Boolean match = passwordEncoder.matches(password, existingUser.get().getPassword());

        // If password matches, creates a new JWT token, session and return the token
        if (match) {
            String token =  createJwtToken(existingUser.get().getId(), new ArrayList<>(), email);   // Creates a new token each time the user logins

            // Save the session
            Session session = new Session();
            session.setToken(token);
            session.setUser(existingUser.get());

            Calendar calendar = Calendar.getInstance();

            calendar.add(Calendar.DAY_OF_MONTH, 30);    // Calendar.DAY_OF_MONTH is a constant in the Calendar class that represents the day of the month. It is used to add or subtract days from the current date. In this case, it is used to add 30 days to the current date to set the expiration date of the JWT token.
            Date datePlus30Days = calendar.getTime();
            session.setExpiringAt(datePlus30Days);

            sessionRepository.save(session);

            return token;
        }
        else {  // If password does not match, throw an exception
            throw new WrongPasswordException("Password is incorrect!");    // Custom Exception
        }
    }

    private String createJwtToken(Long userId, List<String> roles, String email) {
        // Custom claims
        Map<String, Object> dataInJwt = new HashMap<>();
        dataInJwt.put("user_id", userId);
        dataInJwt.put("roles", roles);
        dataInJwt.put("email", email);

        Calendar calendar = Calendar.getInstance();

        calendar.add(Calendar.DAY_OF_MONTH, 30);
        Date datePlus30Days = calendar.getTime();

        String token = Jwts.builder()
                            .expiration(datePlus30Days)    // Headers (A)
                            .issuedAt(new Date())
                            .claims(dataInJwt)      // Payload (B)
                            .signWith(key)          // Key
                            .compact();            // Compact the token to a URL-safe string => Encoded(A).Encoded(B).Encrypt(A+B, key)

        return token;
    }

    /*
      To validate token
        1. Check if token value is present
        2. Check if token is not deleted
        3. Check if token is not expired
    */
    public boolean validate(String token) {
        try {
            // Parse the token and verify the signature using the key (secret key)  => Decrypt(A+B, key) --> This will throw an exception if the token is invalid or has expired
            // If the token is valid, it will return the claims stored in the token
            // If the token is invalid, it will throw an exception
            // This method does not require any storage to validate the token
            Jws<Claims> claims = Jwts.parser()
                                    .verifyWith(key)
                                    .build()
                                    .parseSignedClaims(token);

            Date expiryAt = claims.getPayload().getExpiration();
            Long userId = claims.getPayload().get("user_id", Long.class);

        } catch (Exception e) {
            return false;
        }

        return true;
    }
}
