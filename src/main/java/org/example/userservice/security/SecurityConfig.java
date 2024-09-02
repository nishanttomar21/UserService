/**
 A. TODO [Functions]:
 SecurityFilterChain - It's responsible for defining the security rules and filters that govern how HTTP requests are handled and authenticated. It offers a flexible way to customize security behavior by adding, removing, or modifying filters and their configurations.
 InMemoryUserDetailsManager - It's a simple in-memory implementation of the UserDetailsService interface, used to store and retrieve user details within a Spring Boot application.
 SecurityContext - SecurityContext is a core concept in Spring Security that represents the security information associated with the current execution thread. It's an interface that holds details about the currently authenticated user and their granted authorities.
 JWKSource - JWKSource stands for JSON Web Key Source. It's an interface used in the context of cryptographic operations, particularly in OAuth 2.0 and OpenID Connect implementations.

 1. authorizationServerSecurityFilterChain()
 authorizationServerSecurityFilterChain() is a method that returns a SecurityFilterChain object, which is used by Spring Security to configure the security settings for the application.
 OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http): This applies the default security settings for an OAuth2 authorization server, which includes things like configuring the authentication entry point, CSRF protection, and session management.
 http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()): This enables OpenID Connect 1.0 support for the authorization server.
 http.exceptionHandling(): This configures the exception handling for the authorization server. Specifically, it sets the default authentication entry point to be a LoginUrlAuthenticationEntryPoint that redirects to the /login URL when the user is not authenticated and the request is for a text/html media type.
 http.oauth2ResourceServer(): This configures the OAuth2 resource server functionality, which allows the authorization server to accept access tokens for user information and client registration requests.
 http.build(): This builds the SecurityFilterChain object and returns it.

 2. defaultSecurityFilterChain():
 defaultSecurityFilterChain() is a method that returns a SecurityFilterChain object, which is used by Spring Security to configure the security settings for the application.
 http.authorizeHttpRequests(): This configures the authorization rules for the application. In this case, it's stating that any request to the application must be authenticated.
 http.formLogin(Customizer.withDefaults()): This enables form-based login for the application. This is likely used to handle the redirect to the login page from the authorization server filter chain (as mentioned in the comment).
 http.build(): This builds the SecurityFilterChain object and returns it.

 3. userDetailsService():
 userDetailsService() is a method that returns a UserDetailsService object.
 User.withDefaultPasswordEncoder(): This creates a new UserDetails object using the default password encoder provided by Spring Security. The default password encoder is typically used for development and testing purposes, as it's not recommended for production use.
 .username("user"): This sets the username for the user details to "user".
 .password("password"): This sets the password for the user details to "password".
 .roles("USER"): This assigns the "USER" role to the user details.
 .build(): This builds the UserDetails object.
 return new InMemoryUserDetailsManager(userDetails): This creates an InMemoryUserDetailsManager instance and returns it. The InMemoryUserDetailsManager is an implementation of the UserDetailsService interface that stores user details in memory, rather than in a database or other persistent storage.

 4. registeredClientRepository():
 registeredClientRepository() is a method that returns a RegisteredClientRepository object.
 RegisteredClient.withId(UUID.randomUUID().toString()): This creates a new RegisteredClient object with a randomly generated ID.
 .clientId("oidc-client"): This sets the client ID for the registered client to "oidc-client".
 .clientSecret("{noop}secret"): This sets the client secret for the registered client to "secret". The {noop} prefix indicates that the password is in plain text, which is not recommended for production use.
 .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC): This specifies that the client should use the "client secret basic" authentication method.
 .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE): This enables the "authorization code" grant type for the client.
 .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN): This enables the "refresh token" grant type for the client.
 .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client"): This sets the redirect URI for the client to "http://127.0.0.1:8080/login/oauth2/code/oidc-client".
 .postLogoutRedirectUri("http://127.0.0.1:8080/"): This sets the post-logout redirect URI for the client to "http://127.0.0.1:8080/".
 .scope(OidcScopes.OPENID): This allows the client to request the "openid" scope.
 .scope(OidcScopes.PROFILE): This allows the client to request the "profile" scope.
 .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()): This sets the client settings to require authorization consent from the user.
 .build(): This builds the RegisteredClient object.
 return new InMemoryRegisteredClientRepository(oidcClient): This creates an InMemoryRegisteredClientRepository instance and returns it. The InMemoryRegisteredClientRepository is an implementation of the RegisteredClientRepository interface that stores registered clients in memory, rather than in a database or other persistent storage.

 5. jwkSource():
 jwkSource() is a method that returns a JWKSource<SecurityContext> object.
 KeyPair keyPair = generateRsaKey();: This generates an RSA key pair. The generateRsaKey() method (not shown in this snippet) would create a new public-private key pair.
 RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();: This extracts the public key from the key pair.
 RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();: This extracts the private key from the key pair.
 RSAKey rsaKey = new RSAKey.Builder(publicKey)...: This creates a new RSAKey object, which is a representation of an RSA key in the JWK format. It includes:
     The public key
     The private key
     A randomly generated key ID (kid)
 JWKSet jwkSet = new JWKSet(rsaKey);: This creates a new JWK Set containing the RSA key. A JWK Set is a JSON object that represents a set of cryptographic keys.
 return new ImmutableJWKSet<>(jwkSet);: This creates and returns an immutable JWK Set, which is a thread-safe implementation of JWKSource<SecurityContext>.

 6. generateRsaKey():
 The method generateRsaKey() is declared as private and static, meaning it's an internal helper method for the class it's defined in.
 It creates and returns a KeyPair object, which contains both the public and private keys for RSA encryption.
 Inside a try-catch block:
 a. KeyPairGenerator.getInstance("RSA"): This creates a KeyPairGenerator object specifically for the RSA algorithm.
 b. keyPairGenerator.initialize(2048): This initializes the generator with a key size of 2048 bits. This is a common key size that provides a good balance between security and performance.
 c. keyPair = keyPairGenerator.generateKeyPair(): This generates the actual key pair.
 If any exception occurs during this process (e.g., if the RSA algorithm is not available), it's caught and wrapped in an IllegalStateException. This is a runtime exception indicating that the method was called at an illegal or inappropriate time.
 Finally, the generated keyPair is returned.

 7. jwtDecoder():
 jwtDecoder is a method that takes a JWKSource<SecurityContext> as a parameter and returns a JwtDecoder object.
 OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource): This static method call creates a JwtDecoder using the provided JWK (JSON Web Key) source.
 The jwkSource parameter is typically the JWKSource we created earlier (in the jwkSource() method you showed previously). It contains the public keys used to verify the signatures of JWTs.
 The created JwtDecoder is configured to use the keys from the provided JWKSource to verify the signatures of incoming JWTs.

 The purpose of this JwtDecoder is to:
     Parse incoming JWTs: It can take a JWT string and parse it into its component parts (header, payload, and signature).
     Verify JWT signatures: Using the public keys from the JWKSource, it can verify that the JWT was indeed signed by the corresponding private key and hasn't been tampered with.
     Validate JWT claims: It can check various claims in the JWT, such as expiration time, issuer, audience, etc., to ensure the token is valid and intended for use in this particular context.
     Extract information: Once verified, it can extract the claims and other information from the JWT for use in authentication and authorization decisions.

 This JwtDecoder is a crucial component in the OAuth2 flow, particularly when the authorization server issues JWTs as access tokens or ID tokens. It allows the resource server (or any other component that needs to verify JWTs) to securely validate and extract information from these tokens.
 By using the same JWKSource that was used to create the tokens, this decoder ensures that only tokens created by the authorized issuer (your authorization server) will be accepted and properly decoded.

 8. authorizationServerSettings():
 AuthorizationServerSettings.builder(): This calls the static builder() method on the AuthorizationServerSettings class, which creates a builder object for constructing AuthorizationServerSettings.
 .build(): This method is called on the builder object to construct and return the final AuthorizationServerSettings instance.

 In this case, the builder is created and immediately built without any customizations. This means the function returns an AuthorizationServerSettings object with all default values.
 The AuthorizationServerSettings class is typically used in the context of OAuth 2.0 and OpenID Connect authorization servers. It likely contains configuration options for various aspects of the authorization server, such as:

 Endpoint URLs (e.g., for token issuance, authorization, token revocation)
 Supported grant types
 Token formats and settings
 Consent page configurations

 By using the default settings, this function sets up a basic configuration for an authorization server. In a real-world scenario, you might want to customize these settings by chaining method calls on the builder before calling build().

 B. TODO [Public Key vs Private Key]:
 Public Key:
     Freely distributed and shared with anyone
     Used for encryption and verification of digital signatures
     Cannot be used to derive the private key
     Often represented by a long string of characters
 Private Key:
     Kept secret by the owner
     Used for decryption and creation of digital signatures
     Must be protected and never shared
     Mathematically related to the public key, but computationally infeasible to derive from it

 1. Data -----------------> Public Key -----------------> Encrypted Data (confidentiality)
    Encrypted Data -------> Private Key ----------------> Data
 2. Data -----------------> Private Key ----------------> Digital Signature (authenticity and integrity)
    (Data + Signature) ---> Private Key ----------------> Data

 Digital signatures is used for authentication and non-repudiation, ensuring that the sender of a message cannot deny having sent it. Signatures are used for verifying the integrity and authenticity of the token. The signature is created using the private key and verified using the public key.

 Key differences:
     Distribution:
         Public key: Widely distributed
         Private key: Kept secret
     Usage:
         Public key: Encrypt data, verify signatures
         Private key: Decrypt data, create signatures
     Security:
         Public key: Can be freely shared without compromising security
         Private key: Must be kept secure; if compromised, the entire system is at risk
     Relationship:
        They are mathematically related, but it's computationally infeasible to derive the private key from the public key
     Encryption/Decryption:
         Data encrypted with the public key can only be decrypted with the corresponding private key
     Digital Signatures:
         Created using the private key
         Verified using the public key

 C. TODO [Postman Authentication Configuration]:
 Go to Authorization Tab in Postman
 Choose OAuth 2.0 as the Authorization Type
    1. Auth URL: http://localhost:8080/oauth2/authorize
    2. Access Token URL: http://localhost:8080/oauth2/token
    3. Client ID: postman
    4. Client Secret: password
    5. Scope: images contacts (Permissions: Authorization)
    6. (Tick) Authorize using browser
    7. Add Callback URL -->  Redirect URI (Database): https://oauth.pstmn.io/v1/callback

 */

package org.example.userservice.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Bean
    @Order(1)
    // A Spring Security filter chain for the Protocol Endpoints.
    // Defines a Spring Security configuration for an OAuth2 authorization server (This code sets up the security configuration for an OAuth2 authorization server, enabling OpenID Connect 1.0 support, configuring exception handling, and setting up the resource server functionality. This would be used as part of a larger Spring Security configuration for an application that needs to provide OAuth2 authorization services.)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);  // CSRF (Cross-Site Request Forgery) protection. Basic authentication for server-to-server communication. Security filters for handling authorization requests and responses.
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();    // Build the SecurityFilterChain object
    }

    @Bean
    @Order(2)
    // A Spring Security filter chain for authentication.
    // Sets up the default security settings for the application (This code sets up the default security configuration for the application, requiring all requests to be authenticated and enabling form-based login. This would typically be used in conjunction with the authorizationServerSecurityFilterChain() method to provide a complete security configuration for an application that uses OAuth2 for authentication and authorization.)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    // An instance of UserDetailsService for retrieving users to authenticate.
    // Responsible for loading user details for Spring Security's authentication process (This code sets up a simple in-memory user details service with a single user account having the username "user", the password "password", and the "USER" role. This is typically used for development and testing purposes, as it provides a quick and easy way to set up user authentication without the need for a more complex user management system.)
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))   // Password is encoded using BCryptPasswordEncoder
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails); // user details are present in RAM memory and not database
    }

    // @Bean
    // An instance of RegisteredClientRepository for managing clients.
    // Responsible for managing the registered clients that are allowed to interact with the OAuth2 authorization server ( this code sets up a single registered client with the ID "oidc-client" that uses the "client secret basic" authentication method, the "authorization code" and "refresh token" grant types, and the "openid" and "profile" scopes. The client is configured to require authorization consent from the user, and the redirect and post-logout redirect URIs are set to local development URLs.)
     /** Use only when not using JPA otherwise will get the following error:
          Parameter 0 of method setFilterChains in org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration required a single bean, but 2 were found:
    	        - jpaRegisteredClientRepository: defined in file [/Users/nishanttomar21/IntelliJ IDEA/User Service/target/classes/org/example/userservice/security/repositories/JpaRegisteredClientRepository.class]
    	        - registeredClientRepository: defined by method 'registeredClientRepository' in class path resource [org/example/userservice/security/SecurityConfig.class]
      */
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("postman")
//                .clientSecret(passwordEncoder.encode"password"))  // Password is encoded using BCryptPasswordEncoder
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                .scope(OidcScopes.OPENID)   // Roles and permissions
//                .scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient); // In-memory --> Database (Hence commented code), In-memory is used for testing purpose only
//    }

    @Bean
    // An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
    // This function creates and configures a JSON Web Key (JWK) source, which is used for signing and verifying JSON Web Tokens (JWTs) in an OAuth2 authorization server (This JWK source will be used by the authorization server to sign JWTs (using the private key) and allow clients to verify these JWTs (using the public key). The use of RSA keys allows for asymmetric encryption, where the public key can be freely distributed for JWT verification, while the private key is kept secret and used for signing.)
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey(); // Generate RSA key pair for signing JWTs (encryption and decryption)
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey); // JSON Web Key (JWK) set containing the RSA key pair
        return new ImmutableJWKSet<>(jwkSet);   // Immutable JWK set source
    }

    // An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
    // This function generates an RSA key pair for use in signing and verifying JWTs
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    // An instance of JwtDecoder for decoding signed access tokens.
    // This function creates and configures a JwtDecoder, which is used to decode and verify JSON Web Tokens (JWTs) in an OAuth2 authorization server.
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    // An instance of AuthorizationServerSettings to configure Spring Authorization Server.
    // This function creates and returns an instance of AuthorizationServerSettings using the builder pattern
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}