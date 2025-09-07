# Okta
- Okta is a cloud-based Identity and Access Management (IAM) service. At its core, it acts as a central authority for all things related to identity, who a person is, what they have access to, and how they prove their identity. Okta's primary goal is to securely connect the right people to the right technologies at the right time.

- **Problem Solves**
    - Single Sign-On(SSO): Once login with Okta able access all the organization apps easily with out passwords.
    - MFA: Extra layer security for some sensitive applications
    - Universal Directory: Sync with on-premises directories li AD, workday
    - Lifecycle Management(LCM): Automates the process of creating, updating and deactivating user accounts.
## Common authenication mechanisms supported by Okta

- For modern, custom-built applications, **OIDC** is the preferred standard due to its flexibility and ease of use with modern web and API development. For off-the-shelf enterprise applications, **SAML** is the most common and robust solution. **SWA** is a fallback option for legacy applications that cannot be integrated using a standard protocol.

![Authentication Mechanism with OKTA](/assets/auth_okta.png)


#### 1. SWA (Secure Web Authentication)
> SWA is a simple, non-standard method developed by Okta. It is used for applications that **do not support modern federation protocols** like SAML or OIDC. It works by having Okta store the user's credentials(username and password) for the target.

- Example in a Software Company **SWA**:
- A small, internal tool built years ago for tracking server logs doesn't support modern SSO. The IT team wants to centralize access to it via Okta. They would set up an SWA integration.
    - **Process**: The Okta administrator enters the URL for the log viewer's login page into Okta. They can either set a shared username and password for everyone or allow each user to enter their own credentials once.
    - **User Experience**: When a user clicks the log viewer icon on their Okta dashboard, the Okta browser plugin automatically fills in the login form, and the user is seamlessly logged in. This is a simple, but less secure and less scalable, form of SSO.
- How it does the **SWA autheication and process**:
    1. A user logs into their Okta dashboard.
    2. The user clicks on the tile for the SWA-enabled application.
    3. A special Okta browser plugin (required for SWA) intercepts this click.
    4. Okta securely retrives the user's encrypted credentials for that app from its secure store.
    5. The browser pluin then "types" the username and password into the application's login form and submits it, all without the user seeing credentials.

#### 2. SAML (Security Assertion Markup Language)
> SAML is a widely adapted, XML-based open standard for exchanging authentication and authorization data between two parties: an **Identity Provider (IdP)** and a **Service Provider (SP)**. In this model, Okta acts as the IdP, and the application you're integrating (e.g., Salesforce, Google Workplace) acts as the SP.

- Example in a Software Company **SAML**:
- The company uses Salesforce for its sales team. They want to enable SSO so users don't have to remember a separate Salesforce password.
    - **Process**: An Okta admin configures a SAML connection between Okta and Salesforce. They exchange metadata files that contain public certificates, endpoint URLs, and other configuration details.
    - **User Experience**: When a sales representative navigates to `salesforce.com`, Salesforce immediately redirects them to the company's Okta login page. After they enter their Okta password and perhaps an MFA code, they are automatically redirected back to Salesforce and logged in. They never have to see or remember their Salesforce credentials.
- How it does the **SAML autheication and process**:
    1. **User Access**: A user tries to access a SAML-enabled application (the SP).
    2. **Redirect to IdP**: The SP recognizes that it's configured for SSO and redirects the user's browser to Okta (the IdP).
    3. **Authentication with IdP**: The user authenticates with Okta (if they havn't already in the current session). This is where Okta's robust security policies (MFA, adaptive access) are enforced.
    4. **SAML Assertion**: After successful authentication, Okta generates a digitally signed SAML **assertion**. This XML-based assertion contains information about the authenticated user, such as their username, email, and any other attributes required by the application.
    5. **Redirect Back to SP**: Okta sends the user's browser back to the SP, along with the signed SAML assertion.
    6. **SP Validation and login**: The SP receives the assertion, verifies its digital signature to ensure it came from a trusted source (Okta), and then uses the information inside to create a session for the user and grant them access.

#### 3. OIDC (OpenID Connect)
> OIDC is a modern authentication layer built on top of the **OAuth 2.0 authorization framework**. While OAuth 2.0  is an authorization protocol (granting access to resources), OIDC adds an identity layer that allows an application to verify a user's identity and get basic profile information. It uses JSON Web Tokens (JWTs) as the standard token format, which are more lightweight and easier for web applications and APIs to work with then the XML used in SAML.

- Example in a Software Company **OIDC**
- A software company is building a new customer portal using a modern microservices architecture. They need a fast, secure way for customers to log in without storing their passwords.
    - **Process**: The developers use an Okta SDK to integrate the portal with Okta via OIDC. They register the application in Okta and get a `client_id` and `client_secret`.
    - **User Experience**: A customer visits the portal and clicks "Sign in." The portal redirects them to a customizable Okta-hosted login page. After they log in, Okta sends back a series of tokens. The portal uses these tokens to confirm the customer's identity and create their session. The portal can then use the access token to securely call other internal APIs on behalf of the user (e.g., an API that fetches their past orders).
- How it does the **OIDC autheication and process**:
    1. **User Initiation**: A user clicks a "Login with Okta" button on a modern web application (e.g., a Single-Page Application or mobile app).
    2. **Authorization Request**: The application (the "client") sends an authorization request to Okta's authorization server. This request includes a `client_id`, `redirect_uri`, and requested *scopes* (e.g., `openid`, `profile`, `email`) which specify the user information the app needs.
    3. **User Authentication**: Okta's authorization server handles user authentication.
    4. **Token Exchange**: After the user authenticates, Okta returns an authorization code to the client application. The client then exchanges this code for an **ID Token** (containing user identity information) and an **Access Token** (used to access APIs) from Okta's token endpoint.
    5. **Session Creation**: The application validates the tokens (the `ID Token` in particular) to confirm the user's identity and then create a secure session for them.


#### Other Mechanisms
- **WS-Federation**: A protocol similar to SAML, but primarily used for interoperability with Microsoft-based systems, such as Office 365 and SharePoint. It's less common for new integrations but still relevent for legacy Microsoft applications.
- **OAuth 2.0**: Not an authentication protocol on its own, but rather an **authorization framework**. It's designed to grant a third-party application limited access to a user's resources (e.g., a photo app getting access to your Google Photos) without ever seeing your password. Okta uses OAuth 2.0 externsively for API security, and ODIC is built on top of it to add the authentication piece.




#### SAML INtegration
- Application-> Browse App Catalog

Salesforce developer -> Search Single Sign On
Enable SAML -> Fill the NameIssuer



##### Questions
- Delegated Authentication
- Users comming from the AD provisioning in AD
- Okta users passwords must login with AD passwords
- Authenticators (Google, Okta)
- Salesforce provisioning to Okta 
- Directory -> Profile Editor