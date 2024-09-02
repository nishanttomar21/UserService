/**
 A. TODO [OAuth, Single Sign-On (SSO)]:

 OAuth (Open Authorization)
 * Purpose: OAuth is primarily used for authorization, not authentication. It allows an application (client) to access resources on behalf of a user, without exposing the user’s credentials to the application.
 * It uses access tokens and refresh tokens to manage user authorization and permissions.
 * Access tokens are used to authenticate API requests.
 * Refresh tokens are used to obtain new access tokens when the current one expires.
 * How It Works: OAuth enables users to grant third-party applications limited access to their resources on another service (like Google, Facebook, etc.) without sharing their username and password. For example, when you use a service to log in to an app with your Google account, you're using OAuth.
 * Flow:
 * The user is redirected to the service provider's authorization server.
 * The user authenticates with the provider (e.g., Google).
 * The provider grants the application an access token, which allows the application to access the user's resources on the provider’s service.
 * Tokens: OAuth uses tokens (typically, access and refresh tokens) to grant and manage access.
 * Common Use Cases: Allowing a third-party app to access your social media accounts, integrating with APIs like Google or Facebook, etc.
 * Example: When you sign in to a website using your Google account and the website asks for permission to access your Google contacts, OAuth is used to authorize the website's access to your contacts. Login using gmail, apple, facebook etc

 SSO (Single Sign-On)
 * Purpose: SSO is a user authentication process that allows a user to access multiple applications or services with a single set of login credentials (typically username and password).
 * SSO often leverages OAuth to achieve this.
 * The authentication provider (e.g., Google, Apple) issues an access token to the application, which is then used for subsequent authentication within the SSO context.
 * How It Works: Once a user logs in to one application, they are automatically logged into other related applications without having to re-enter their credentials.
 * Flow:
 * The user authenticates with the central identity provider (IdP) once.
 * The IdP generates a session or token that allows the user to access other connected services without re-authenticating.
 * Common Protocols: SAML (Security Assertion Markup Language), OpenID Connect.
 * Common Use Cases: Enterprise environments where employees need to access multiple internal applications (e.g., email, intranet, HR systems) with a single login, consumer environments where you log into multiple related services from the same provider.
 * Example: A company using SSO might let employees log in to all corporate apps using their company email and password through a single portal.

 Key Differences
 * Purpose: OAuth is for authorization (granting access to resources), while SSO is for authentication (logging in to multiple systems with one set of credentials).
 * Scope: OAuth is often used for third-party app access, whereas SSO is typically used within an organization or a suite of applications.
 * User Interaction: With OAuth, users authorize an application to act on their behalf. With SSO, users simply log in once and gain access to multiple services.
 * Protocols: OAuth usually uses tokens for API access, whereas SSO may use protocols like SAML or OpenID Connect to manage authentication across services.

 Combining OAuth and SSO
 In some cases, OAuth and SSO are used together. For example, when using OAuth with OpenID Connect, the protocol supports both authentication (SSO) and authorization, enabling a seamless login experience across multiple applications while also granting permissions to resources.

 Conclusion
 * OAuth: Think "authorization for third-party apps."
 * SSO: Think "login once, access everything."
 * Authentication —> Authorization


 B. TODO [The authentication provider (e.g., Google, Apple) issues an access token to the application as a result of the OAuth authorization flow]:

 Here's a breakdown of how this process typically works:
 1. User Authorization: When a user logs in to LinkedIn using their Google or Apple account, they are redirected to the authentication provider's website. The user is prompted to grant permission to LinkedIn to access their data.
 2. Authorization Code: If the user grants permission, the authentication provider issues an authorization code to LinkedIn. This code represents the user's consent for LinkedIn to access their data.
 3. Token Exchange: LinkedIn sends the authorization code to the authentication provider's token endpoint.
 4. Access Token Issuance: The authentication provider validates the authorization code and, if it's valid, issues an access token to LinkedIn. This access token represents the user's authorization to access their data.
 5.
 The access token is then used by LinkedIn to make authenticated API calls to the authentication provider to retrieve user information. This allows LinkedIn to access the user's data without requiring the user to re-enter their credentials for each request.

 In essence, the authentication provider acts as a trusted intermediary, issuing the access token to LinkedIn based on the user's authorization. This ensures that LinkedIn only has access to the data that the user has explicitly granted permission for.


 C. TODO [Token vs. JWT: A Comparison]:
 Tokens and JSON Web Tokens (JWTs) are both mechanisms used for authentication and authorization in web applications, but they have distinct characteristics and use cases.

 Tokens
 * General Term: A token is a small piece of text that represents a user's identity or session.
 * Types: Tokens can be session tokens, access tokens, refresh tokens, etc.
 * Purpose: Primarily used for authentication and session management.
 * Implementation: Can be implemented in various ways, depending on the specific use case and technology stack.

 JSON Web Tokens (JWTs)
 * Specific Format: A JWT is a standard format for representing claims securely and compactly.
 * Structure: A JWT consists of three parts: a header, a payload, and a signature.
 * Claims: The payload contains claims about the user, such as their identity, permissions, and expiration time.
 * Security: JWTs are typically signed using a secret key or a public/private key pair to ensure integrity and authenticity.
 * Self-Contained: JWTs are self-contained, meaning they don't require additional server-side state to validate.

 Key Differences
 Feature	            Token	                                JWT
 Format	            Generic string	                Standardized JSON structure
 Claims	            Can contain any information	    Contains claims about the user and the token
 Security	        Depends on implementation	    Built-in security features (signature, claims)
 Self-Contained	    May require server-side state	Self-contained

 When to Use Which
 * Tokens: For general-purpose authentication and session management, especially in older or custom-built systems.
 * JWTs: For scenarios that require:
 * Self-contained, secure tokens
 * Interoperability between different systems
 * Easy verification and decoding

 In modern web applications, JWTs are often preferred due to their standardized format, security features, and ease of use.

 JWT Format: A.B.C
 1. Header (A): This is the first part of the JWT. It's a Base64Url-encoded JSON object that typically contains two fields:
 * alg: The signing algorithm being used, like HS256 (HMAC SHA-256).
 * typ: The type of token, which is usually JWT.
 2. Payload (B): The second part of the JWT is the payload, which is also a Base64Url-encoded JSON object. This contains the claims or statements about the entity (usually the user) and additional data. Common claims include:
 * sub: Subject (the identifier for the user).
 * iat: Issued at (timestamp of when the token was created).
 * exp: Expiration time (when the token will expire).
 3. Signature (B): The third part of the JWT is the signature. This is created by taking the encoded header and payload, concatenating them with a period (.), and then applying the algorithm specified in the header to generate a hash. The signature ensures that the token hasn't been tampered with.
 A: Base64Url-encoded header (Encode(A))
 B: Base64Url-encoded payload (Encode(B))
 C: Signature (Encrypt(A+B, secret_key))

 HEADER:ALGORITHM & TOKEN TYPE
 {
 "alg": "HS256",
 "typ": "JWT"
 }

 PAYLOAD:DATA
 {
 "sub": "1234567890",
 "name": "John Doe",
 "iat": 1516239022
 }

 VERIFY SIGNATURE
 HMACSHA256(
 base64UrlEncode(header) + "." +
 base64UrlEncode(payload),
 your-256-bit-secret_key
 )


 NOTE: JWT doesn’t work when you want to: (will have to use database for these implementations )
 1. Logout from all devices or 1 device
 2. Limit the number of login at the same time (Scaler, Swiggy)
 3. Limit the number of users watching at the same same (Netflix, JioCinema, Hotstar)

 JWTs are self-contained, meaning they contain all the necessary information about the user and their permissions within the token itself. This makes them ideal for use in stateless applications and microservices where maintaining server-side session state is not desirable. JWTs are commonly used in modern web applications and APIs for authentication and authorization purposes.


 D. TODO [OAuth 1.0 vs OAuth 2.0]:
 1. Authorization Flow:
     OAuth 1.0:
         Relies on cryptographic signatures for each request, making it more complex.
         Involves multiple steps, including obtaining a Request Token, redirecting the user for authorization, and then exchanging the Request Token for an Access Token.
     OAuth 2.0:
         Simplifies the process by using access tokens (typically bearer tokens), which don't require signing each request.
         Offers multiple grant types (authorization code, client credentials, implicit, password, etc.) to accommodate various use cases.
 2. Security Mechanism:
     OAuth 1.0:
         Uses HMAC-SHA1 or RSA-SHA1 for signing requests.
         Requires both a Consumer Key/Secret and a Token/Token Secret for every request, ensuring that requests can't be tampered with.
     OAuth 2.0:
         Primarily relies on HTTPS to secure communication, with tokens being passed in headers or query parameters.
         Access tokens are typically Bearer tokens, which can be used by anyone who has them, making the use of HTTPS crucial for security.
         Optional extensions, such as Proof Key for Code Exchange (PKCE) and OAuth 2.1, improve security by adding mechanisms to prevent attacks.
 3. Complexity:
    OAuth 1.0:
         More complex due to the signature-based authentication, requiring the generation of cryptographic signatures for each request.
         More challenging to implement and debug because of the complexity of signing and verifying each request.
    OAuth 2.0:
         Simplified, with a focus on ease of implementation.
         No need to sign each request, reducing the complexity for developers.
         However, OAuth 2.0 is also flexible, with optional components that can add complexity if needed (e.g., token introspection, revocation, scopes).
 4. Use Cases:
     OAuth 1.0:
         Designed primarily for web applications.
         Ideal for cases where a high level of security and integrity is required, but at the cost of added complexity.
     OAuth 2.0:
         Designed for a broader range of applications, including mobile and native apps, single-page applications (SPAs), and traditional web applications.
         More suitable for modern, distributed architectures due to its flexibility and the availability of various grant types.
 5. Deprecation and Adoption:
     OAuth 1.0:
         Largely deprecated in favor of OAuth 2.0 due to its complexity and the difficulty of implementation.
         Still used in some legacy systems, but not recommended for new projects.
     OAuth 2.0:
         The industry standard for authorization today, widely adopted by major platforms like Google, Facebook, GitHub, and others.
         Continually evolving with security improvements (e.g., OAuth 2.1, which is designed to address some of the security concerns in OAuth 2.0).
 6. Token Types:
     OAuth 1.0:
        Uses Request Tokens and Access Tokens, with the latter requiring both a token and a token secret.
     OAuth 2.0:
        Uses Bearer tokens (most common), JWT (JSON Web Tokens), or MAC tokens (less common).
 7. Token Expiration and Revocation:
     OAuth 1.0:
        Token revocation is manual and less standardized.
     OAuth 2.0:
         Supports refresh tokens, allowing access tokens to be refreshed without requiring user interaction.
         Supports token revocation and introspection endpoints for better management.
 8. Resource Access:
     OAuth 1.0:
        Each request must include a signature, and the server verifies this signature to ensure the integrity and authenticity of the request.
     OAuth 2.0:
        Requests are authenticated by simply including a token in the HTTP Authorization header. Security is ensured through HTTPS.

 Summary:
     OAuth 1.0 offers more security through request signatures but is complex and difficult to implement, leading to it being largely deprecated.
     OAuth 2.0 is easier to implement, more flexible, and supports a wider range of use cases, but relies heavily on HTTPS for security. It's the industry standard today and continues to evolve with updates like OAuth 2.1.

 For new applications, OAuth 2.0 is generally recommended due to its flexibility, ease of use, and widespread support.

 */