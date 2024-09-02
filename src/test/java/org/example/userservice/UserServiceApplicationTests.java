// registeredClientRepository() is a method that returns a RegisteredClientRepository object.
//        RegisteredClient.withId(UUID.randomUUID().toString()): This creates a new RegisteredClient object with a randomly generated ID.
// .clientId("oidc-client"): This sets the client ID for the registered client to "oidc-client".
//        .clientSecret("{noop}secret"): This sets the client secret for the registered client to "secret". The {noop} prefix indicates that the password is in plain text, which is not recommended for production use.
//        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC): This specifies that the client should use the "client secret basic" authentication method.
//        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE): This enables the "authorization code" grant type for the client.
//        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN): This enables the "refresh token" grant type for the client.
//        .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client"): This sets the redirect URI for the client to "http://127.0.0.1:8080/login/oauth2/code/oidc-client".
//        .postLogoutRedirectUri("http://127.0.0.1:8080/"): This sets the post-logout redirect URI for the client to "http://127.0.0.1:8080/".
//        .scope(OidcScopes.OPENID): This allows the client to request the "openid" scope.
// .scope(OidcScopes.PROFILE): This allows the client to request the "profile" scope.
// .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()): This sets the client settings to require authorization consent from the user.
//        .build(): This builds the RegisteredClient object.
// return new InMemoryRegisteredClientRepository(oidcClient): This creates an InMemoryRegisteredClientRepository instance and returns it. The InMemoryRegisteredClientRepository is an implementation of the RegisteredClientRepository interface that stores registered clients in memory, rather than in a database or other persistent storage.

package org.example.userservice;

import org.example.userservice.security.repositories.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@SpringBootTest
class UserServiceApplicationTests {
    @Autowired
    private JpaRegisteredClientRepository registeredClientRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Test
    void contextLoads() {
    }

    @Test
    // This test method is used to create new clients and store it into the database
    void storeRegisteredClientIntoDB() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                                    .clientId("postman")
                                                    .clientSecret(passwordEncoder.encode("password"))   // Password is encoded using BCryptPasswordEncoder
                                                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                                    .redirectUri("https://oauth.pstmn.io/v1/callback")
                                                    .postLogoutRedirectUri("https://oauth.pstmn.io/v1/callback")
                                                    .scope(OidcScopes.OPENID)
                                                    .scope(OidcScopes.PROFILE)
                                                    .scope("ADMIN")
                                                    .scope("STUDENT")
                                                    .scope("MENTOR") // Role
                                                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                                                    .build();

        registeredClientRepository.save(oidcClient);
    }
}
