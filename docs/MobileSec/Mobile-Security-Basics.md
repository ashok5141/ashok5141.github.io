
# OWASP Mobile Top 10
- It will categorises top 10 vulnerabilites acroos the world, First one is most common one.

![Owasp Mobile top 10](https://owasp.org/www-project-mobile-top-10/assets/images/comparison-owasp-10.png)


| Serial Number | Name of the Vulnerability | How to Find This Using Tools | How to Mitigate This |
| :--- | :--- | :--- | :--- |
| M1 | **Improper Credential Usage**: This vulnerability occurs when an application stores credentials like API keys, tokens, or passwords in an insecure manner, such as hardcoding them directly in the app's source code or configuration files. | Use static analysis tools like **MobSF** to decompile the app and search for hardcoded API keys, tokens, and credentials in the source code. Use a proxy tool like **Burp Suite** to intercept network traffic and check for authentication credentials being sent in plaintext or weak formats. | Do not embed or hardcode any credentials directly in the app. Utilize secure credential storage, such as a mobile key management service or platform-specific secure storage (e.g., Android Keystore, iOS Keychain). Implement server-side authentication with temporary, short-lived tokens. |
| M2 | **Inadequate Supply Chain Security**: This refers to risks introduced by using third-party libraries, SDKs, or other components that may contain known vulnerabilities, outdated code, or malicious functionality. | Use dependency scanning tools like **Snyk** or **OWASP Dependency-Check** to identify known vulnerabilities in third-party libraries and SDKs used in the app. Analyze the app's build process to ensure all dependencies are from trusted sources. | Maintain a comprehensive Software Bill of Materials (SBOM) for the app. Regularly update all third-party libraries and dependencies to the latest, most secure versions. Vet all external components for known vulnerabilities before integration. |
| M3 | **Insecure Authentication/Authorization**: This vulnerability involves flaws in how an application verifies user identity (authentication) or grants access to resources (authorization), allowing an attacker to bypass security controls and gain unauthorized access. | Use a proxy tool like **Burp Suite** to manipulate authentication requests. Try to bypass the login process by replaying requests with a different user ID, or by using stolen/expired session tokens. Test for weak password policies, lack of MFA, and improper session management. | Implement strong authentication policies, including multi-factor authentication (MFA) and account lockout after repeated failed login attempts. Ensure all authentication and authorization logic is performed on the server-side, and that sessions are properly managed and invalidated after a period of inactivity or on logout. |
| M4 | **Insufficient Input/Output Validation**: This occurs when an application fails to properly validate, sanitize, or encode user-provided data, which can lead to injection attacks like SQL injection, command injection, or Cross-Site Scripting (XSS). | Use a proxy tool like **Burp Suite** to modify input fields with common attack strings for SQL injection, command injection, and Cross-Site Scripting (XSS). Observe how the app and its backend handle these malicious inputs. Check for reflected or stored XSS vulnerabilities. | Validate all user input on both the client and server side. Use parameterized queries for database interactions to prevent SQL injection. Sanitize and encode all output displayed in the app to prevent XSS and other injection attacks. |
| M5 | **Insecure Communication**: This vulnerability arises from the failure to use encryption or from using weak encryption during data transmission between the mobile app and its server, making data susceptible to interception and eavesdropping. | Use a proxy tool like **Burp Suite** to intercept network traffic. Check if the app is using HTTP instead of HTTPS. Analyze the TLS/SSL configuration to ensure a secure cipher suite is used. Test for Man-in-the-Middle (MITM) attacks to see if the app accepts insecure connections or fails to validate server certificates. | Enforce the use of TLS/SSL for all network communication. Implement strong certificate pinning to prevent MITM attacks and ensure the app only communicates with trusted servers. Avoid allowing the app to accept self-signed or invalid certificates. |
| M6 | **Inadequate Privacy Controls**: This issue is related to the app's failure to handle sensitive user data in a secure and compliant manner, such as storing personal information unencrypted or transmitting it to unauthorized third parties without user consent. | Use a file system explorer on a rooted/jailbroken device to check for sensitive personal data (e.g., PII, health information) stored insecurely. Analyze network traffic with a proxy tool to see if private data is transmitted unencrypted or to unauthorized third-party services. | Minimize the collection and storage of sensitive user data. Anonymize or encrypt all private data both in transit and at rest. Ensure data handling complies with privacy regulations like GDPR, HIPAA, and other country-specific laws. |
| M7 | **Insufficient Binary Protections**: This involves a lack of security measures in the app's executable code, which can make it easy for attackers to reverse engineer, tamper with, or debug the app to discover its inner workings or bypass controls. | Use dynamic analysis tools like **Frida** or **Objection** to test for and bypass security controls like root/jailbreak detection, debugger detection, or anti-tampering checks. Use a static analysis tool like **MobSF** to identify if the app binary has been obfuscated or protected against reverse engineering. | Implement binary hardening techniques such as code obfuscation, anti-tampering, and anti-debugging. Use strong root/jailbreak detection and integrity checks to prevent the app from running on a compromised device. |
| M8 | **Security Misconfiguration**: This occurs when the application or its underlying server and components are configured with insecure settings, such as having debug mode enabled in a production environment, or using default passwords for admin interfaces. | Use a static analysis tool like **MobSF** to review the app's manifest file (e.g., AndroidManifest.xml) for insecure settings such as debuggable flags enabled in production, or public-facing components that shouldn't be. On the server side, check for open ports, default credentials, or directory listings. | Adhere to secure configuration baselines. Disable debugging and other development-related features in production builds. Follow the principle of least privilege by ensuring all components have minimal permissions required to function. |
| M9 | **Insecure Data Storage**: This vulnerability occurs when an application stores sensitive data on the mobile device's local storage in an unencrypted or easily accessible format, allowing attackers with physical access or a compromised device to retrieve it. | Use a file system viewer on a rooted/jailbroken device to inspect the app's data directories. Look for sensitive data in databases (`.db`), shared preferences (`.xml`), or unencrypted files. Use a tool like **SQLite Browser** to open and inspect local databases. | Avoid storing sensitive data on the device whenever possible. When necessary, use the platform's secure storage APIs (e.g., iOS Keychain, Android Keystore). Encrypt all sensitive data at rest using strong encryption algorithms. |
| M10 | **Insufficient Cryptography**: This is the failure to use strong, modern, and well-vetted cryptographic algorithms to protect data. This includes using outdated or broken encryption methods, or implementing custom, flawed crypto logic. | Use a static analysis tool like **MobSF** to identify the cryptographic algorithms used by the app. Use a proxy tool to analyze encrypted network traffic for weak or outdated cipher suites. Attempt to tamper with encrypted data to check for proper integrity checks. | Use strong, industry-standard cryptographic algorithms (e.g., AES-256). Avoid implementing custom or homegrown cryptographic solutions. Ensure proper key management and secure key exchange. Do not use outdated or broken algorithms like MD5 or RC4. |
| **New 1** | **Data Leakage**: This occurs when sensitive information is unintentionally exposed and stored in insecure locations like logs, crash reports, or temporary files, making it accessible to other applications or attackers. | Use a proxy tool like **Burp Suite** to capture all network traffic and analyze it for sensitive data being sent or received. On a rooted/jailbroken device, use a file system explorer to check log files (`logcat` for Android) and local storage for plaintext sensitive information. | Avoid logging or storing any sensitive data on the device. Ensure that any temporary files are immediately and securely deleted after use. Use the device's secure storage mechanisms and encrypt data both at rest and in transit. |
| **New 2** | **Hardcoded Secrets**: This vulnerability involves embedding confidential information, such as API keys, cryptographic keys, or credentials, directly into the app's source code or configuration files. This allows attackers to easily extract them through reverse engineering. | Use static analysis tools like **MobSF** or a decompiler like **JADX** to analyze the app's code. Search for hardcoded strings that look like API keys, URLs, or other secrets. Run the `strings` command on the app binary to quickly find plaintext strings. | Do not hardcode secrets. Use a secure key management system, store credentials on a remote server, or leverage platform-specific secure storage (e.g., iOS Keychain, Android Keystore). |
| **New 3** | **Insecure Access Control**: This is a failure to properly restrict a user's access to certain functions or data. An attacker can exploit this to access information or perform actions they are not authorized for, either as a different user (horizontal privilege escalation) or as an administrator (vertical privilege escalation). | Use a proxy tool like **Burp Suite**. Authenticate as a standard user, then try to access privileged endpoints or data by manually changing request parameters. Test for both horizontal (accessing another user's data by changing a user ID) and vertical (accessing an admin-only function) privilege escalation. | Enforce strict access control rules on the server side for every request. Never rely on client-side checks for authorization. Implement the principle of least privilege, ensuring users can only access what is absolutely necessary for their role. |
| **New 4** | **Path Overwrite and Path Traversal**: This vulnerability allows an attacker to read or write files outside of the app's intended directory. It is often caused by insufficient validation of user input that includes file paths, allowing an attacker to use special characters like `../` to navigate the file system. | Use a proxy tool like **Burp Suite** to inject path traversal sequences (`../`, `..\`) into any user-controllable input that involves file operations, such as file uploads or image loading. Check if the app or server reads or writes files to an unintended location. | Sanitize all user input related to file paths. Implement a strict allow-list of acceptable file names and paths. Use platform-specific file system APIs that are designed to prevent path traversal attacks. |
| **New 5** | **Unprotected Endpoints**: This vulnerability affects the app's components (like Android Activities, Services, or iOS Deeplinks) that can be invoked from other apps. If these components are not properly secured, a malicious app can call them and pass malicious data to compromise the application. | Use static analysis tools like **MobSF** to review the app's manifest file and identify all exported components. On a test device, use tools like **`adb`** (for Android) to try and launch these components with malicious data to see if a crash or other unexpected behavior occurs. | Ensure that app components are not exported unless absolutely necessary. When an endpoint must be exposed, protect it with proper permissions. Implement robust input validation and sanitization for any data received by these endpoints from external sources. |
| **New 6** | **Unsafe Sharing**: This vulnerability occurs when an application uses insecure methods for inter-app communication, which can lead to the unintended exposure of sensitive data to other applications on the same device. This often involves using insecure intents or content providers. | Use dynamic analysis and a file system viewer on a rooted/jailbroken device to monitor data being passed between apps. Look for sensitive data being written to shared directories that are not properly secured or for broad intent filters that could be intercepted by other apps. | Use explicit and secure intents for inter-app communication. When sharing sensitive data, use private Content Providers and enforce strict permissions to ensure only authorized applications can access the data. |




## OWASP MASVS vs MASTG
- OWASP MASVS and OWASP MASTG are two foundational frameworks for mobile security, but they serve different purpose.
- They provide a comprehensive approch that goes far beyond the high-level OWASP Top 10 list.

| | OWASP MASVS | OWASP MASTG |
|:-|:-|:-|
| FullName | Mobile Application Security Verification Standard | Mobile Application Security Testing Guide |
| Purpose | A **standard** for defining what a secure mobile app should look like. It's a checklist of security controls. | A **guide** on how to perform security testing. It provides detailed methodologies and test cases. |
| Focus | **What** to secure | **How** to test |
| Analogy | A list of requirements for building a secure vault. | The instruction manual for a professional vault cracker. | 

### MASVS - During the Design Phase
- **When**: Before developmet begins.
- **How**: You use the MASVS as a checklist to define the security requirement for the application. You might specify that your app must meet a certain level of security (e.g., L1:Standard Security or L2: Defense-in-Deapth).
- *Example*: To meet a L1 requirement, you'd mandate that the app "does not store sensitive data in an unencrypted manner." This sets a clear, verifiable security goal.


##### MASVS-STORAGE: Storage
- Mobile applications handle a wide variety of sensitive data. such as Personally Identifiable Information (PII), Cryptographic material, secrets, and API keys, that often need to be stored locally. 
- This sensitive data may be stored in private locations, such as the app's internal storage, or in public folders that are accessiable by the user or other apps installed on the device.
- However, sensitive data can also be unitentionally stored or exposed to publicly accessible locations, typically as a side-effect of using certain APIs or system capabilities such as backups or logs.

| ID | Statement |
|:-|:-|
| MASVS-STORAGE-1 | The app securely stores sensitive data |
| MASVS-STORAGE-2 | The app prevents leakage of sensitive data |

##### MASVS-CRYPTO: Cryptography
- Cryptography is essential for mobile apps because mobile devices are highly portable amd can be easily lost or stolen.
- This means that an attacker who gains physical access to a device can potentially access all the sensitive data stored on it, including passwords, financial information, and personally identifiable information.
- Cryptography provides a means of protecting this sensitive data by encrypting it so that it cannot be easily read or accessed by an unauthorized user.

| ID | Statement |
|:-|:-|
| MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. |
| MASVS-CRYPTO-2 | The app performs key management according to industry best practices |

##### MASVS-AUTH: Authentication and Authorization
- Authenication and authorization are essential components of most mobile apps, especially those that connect to a remote service.
- These mechanisms provide an added layer of security and help prevent unauthorized access to sensitive user data.
- Althrough the enforcement of these mechanisms must be on the remote endpoints, it is equally important for the app to follow relevent best practice to ensure the secure use of the involved protocols.
- Mobile apps often use different forms of authentication, such as biometrics, PIN, or multi-factor authentication code generators, to validate user identity.
- These mechanisms must be implemented correctly to ensure their effectiveness in preventing unauthorized access.
- Additionally, some apps may rely solely on local app authentication and may not have a remote endpoint. 
- In such cases, it is critical to ensure that local authentication mechanisms are secure and implemented following industry best practices.

| ID | Statement |
|:-|:-|
| MASVS-AUTH-1 | The app uses secure authentication and authorization protocols and follows the relevant best practices |
| MASVS-AUTH-2 | The app performs local authentication securely according to the platform best practices |
| MASVS-AUTH-3 | The app secures sensitive operations with additional authentication |

##### MASVS-NETWORK: Network Communication
- Secure networking is a critical aspect of mobile app security, particularly for apps that communicate over the network.
- In order to ensure the confidentiality and integrity of data in transit, developers typically rely on encryption and authentication of the remote endpoint, such as through the use of TLS.
- However, there are numerous ways in which a developer may accidentally disable the platform secure defaults or bypass them entirely by utilizing low-level APIs or third-party libraries.

| ID | Statement |
|:-|:-|
| MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices |
| MASVS-NETWORK-2 | The app performs identity pinning for all remote endpoints under the developer's control |

##### MASVS-PLATFORM: Platform Interaction
- The security of mobile apps heavily depends on their interaction with the mobile platform, which often involves exposing data or functionality intentionally through the use of platform-provided inter-process communication (IPC) mechanisms and WebViews to enhance the user experience. 
- However, these mechanisms can also be exploited by attackers or other installed apps, potentially compromising the app's security.

| ID | Statement |
|:-|:-|
| MASVS-PLATFORM-1 | The app uses IPC mechanisms securely |
| MASVS-PLATFORM-2 | The app uses WebViews securely |
| MASVS-PLATFORM-3 | The app uses the user interface securely |

##### MASVS-CODE: Code Quality
- Mobile apps have many data entry points, including the UI, IPC, network, and file system, which might receive data that has been inadvertently modified by untrusted actors. 
- By treating this data as untrusted input and properly verifying and sanitizing it before use, developers can prevent classical injection attacks, such as SQL injection, XSS, or insecure deserialization. 
- However, other common coding vulnerabilities, such as memory corruption flaws, are hard to detect in penetration testing but easy to prevent with secure architecture and coding practices.
- Developers should follow best practices such as the OWASP Software Assurance Maturity Model [SAMM](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) ↗ and NIST.SP.800-218 Secure Software Development Framework [SSDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) ↗ to avoid introducing these flaws in the first place.

| ID | Statement |
|:-|:-|
| MASVS-CODE-1 | The app requires an up-to-date platform version |
| MASVS-CODE-2 | The app has a mechanism for enforcing app updates |
| MASVS-CODE-3 | The app only uses software components without known vulnerabilites |
| MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs |

##### MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering
- Defense-in-depth measures such as code obfuscation, anti-debugging, anti-tampering, and runtime application self-protection (RASP) can increase an app's resilience against reverse engineering and specific client-side attacks. 
- They add multiple layers of security controls to the app, making it more difficult for attackers to modify code or extract sensitive information.
- Business and Commercial Perspective
    - Theft or compromise of proprietary algorithms, trade secrets, customer data, AI or machine learning models
    - Fraud, cheating, or revenue leakage in online games, financial apps, or subscription models
    - Legal and reputational damage due to breach of contracts or regulations
    - Damage to brand reputation due to negative publicity or customer dissatisfaction
- Transparency and Open Audit Perspective
    - It reduces transparency of what the compiled application is doing
    - Independent verification of the compiled application is more difficult
    - The diversity of smartphone operating systems can lead to false positives, potentially excluding legitimate users
    - In case these concerns are valid for the target application, we recommend applying the following principles:
        - Open source distribution of source code for independent audits
        - Security must rely on verifiable design, strong cryptography, and server-side validation
        - Anti-tampering or obfuscation techniques must not be used as a substitute for proper security architecture
        - Controls should prevent cheating or malicious modification without hindering legitimate users and legitimate analysis or oversight
- Platform Lock-in
    - The application and its own memory and files
    - The underlying OS
- Malware and Testing Perspective
    - Conceal malicious functionality
    - Evade security tools or app store review
    - Frustrate researchers and hinder forensic analysis

| ID | Statement |
|:-|:-|
| MASVS-RESILIENCE-1 | The app validates the integrity of the platform |
| MASVS-RESILIENCE-2 | The app implements anti-tampering mechanisms |
| MASVS-RESILIENCE-3 | The app implements anti-static analysis mechanisms |
| MASVS-RESILIENCE-4 | The app implements anti-dynamic analysis techniques |

##### MASVS-PRIVACY: Privacy
- The main goal of MASVS-PRIVACY is to provide a baseline for user privacy. It is not intended to cover all aspects of user privacy, especially when other standards and regulations such as ENISA or the GDPR already do that. 
- We focus on the app itself, looking at what can be tested using information that's publicly available or found within the app through methods like static or dynamic analysis.

| ID | Statement |
|:-|:-|
| MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources |
| MASVS-PRIVACY-2 | The app prevents identification of the user |
| MASVS-PRIVACY-3 | The app is transparent about data collection and usage |
| MASVS-PRIVACY-4 | The app offers user control over their data |








### MASTG - During the Testing Phase