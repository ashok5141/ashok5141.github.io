Practical Secure by Design: Threat Modeling to Build Resilient Products

# Secure by Design
## Secure by Design


``` mermaid
sequenceDiagram
  autonumber
  Hacker->>Twitter: Hacker wants access to twitter account of @Ashok
  Note right of Hacker: I want Ashok Twitter
  loop Check
      Twitter->>Twitter: Inorder access twitter first get access gmail or icloud.
  end
  Note right of Hacker: Decided to go with iCloud!
  Hacker-->>Apple: Hacker called iCloud told want reset the password
  Hacker-->>Apple: Apple in order to do that they need to verify the Full name, Billing address, Last 4 digits of credit card
  Twitter-->>Apple: Great!
  loop Check
      Apple->>Apple: Full name, Billing address, Last four digits of a credit card on file
  end
  Hacker-->>Apple: From internet got access to Full name, Billing address.
  Note right of Hacker: Decided to get credit card last 4 digits from the Amazon 
  Hacker-->>Amazon: Hacker called Amazon then asked the last 4 digits of credit card with user details
  Amazon-->>Hacker: You can add the new credit card
  loop Check
      Amazon->>Amazon: Can not retrive entire but you can add new card
  end
  Amazon-->>Hacker: Authenticated, Got last 4 digit of old card, Authrozied by given added card
  Hacker-->>Apple: Called told the Fullname, Billeding, Address, Last 4 digits of credit card 
  Hacker-->>Twitter: Reset the password got access to Twitter
```

- In the above scenario [Link](https://www.wired.com/2012/08/apple-amazon-mat-honan-hacking/)
    - No password compromise
    - No malware
    - No code vulnerability (No code related vulnerability)
- This vulnerability exploited due `Logical and design flaws` in the application

##### Understanding design flaws in a real-world scenario
| 1. Weak Identity Verification | 2. Insecure Account Recovery Process | 3. No Anomaly Detection |
| :- | :- | :- |
| Flaw: Both Amazon and Apple relied on `easily obtainable information` like name, email, billing address and last 4 digits of credit card to verify identity over the phone | Flaw: Amazon allowed a new credit card to be added to an account after only weak checks and then let that `new card be used` to reset the password. | Flaw: Multiple sensitive actions happened across accounts (adding new card, password reset, new recovery email, remote wipe) all with `no alerts or lockouts`|
| `Why it's problem`: This data can be `scraped, leaked, or guessed`. There was no real verification of who was calling. | `Why it's problem`: This creates a `circular depandency` in which an attacker can add a verification method and immediately use it to take control. | `Why it's problem`: The attack moved fast, and no system noticed or wanted the legitimate user. |

- **Attacker Mindset**
    - How to think like an attacker
- **Security Principles**
    - Basic fundamentals
- **Security by Design for AI**
    - Making the bot do secure things

##### Fundamentals
- `Secure by design` is a way of building software where security isn't an afterthought. We don't want to wait for something to break, We think about security from the start from planning to writing code to launching the product. Security is built into every step
    - We think about security requirements and possiable threats, when we design things.
    - We use threat modeling to ask, what could go wrong?, How could someone break this? We also follow secure coding practices. So that we don't leave easy bugs or loopholes.
    - Multi-layered defenses (defense in depth), secure configuration and regular monitoring are a part of standard processess.
    - The goal is to build products that are secure out of the box, We don't want to make assumptions about user's technical knowledge and want to make sure that the users don't have to do any additional complex configurations.
- CISA: Three Core Principles [YouTube](https://www.youtube.com/watch?v=W17uB1FnYDY)
    - Take ownership of customer security outcomes.
    - Embrace radical transparency and accountability.
    - Lead organizationally with security as a priority.

##### CISA pledge: Secure by design
| Security Requirements and Threat Modeling | Secure Coding | Layered Defense and Continous Monitoring |
| :- | :- | :- |
| We don't just start building blindly, We take time to think. We think about what are we trying to protect, Who might try to break in, What could go wrong, This helps us to design smarter and catch a lot of problems early before write any code. | When we do write code, we do it in a way that's defensive, clean, and safe by default. Consider something like no hard coded credentials, no trusting user inputs blindly, no shortcuts that lead to vulnerabilities later. | Even if we've built everything right, we know something could go wrong, So we add multiple layers of protection. Like Firewalls, access controls, logging. We do this so that no single failure can brings down the system and we keep watching, continous monitering means we watch weird behaviour quickly. Respond fast, and keep improving security even after the launch |

##### Fictional company case study

https://lnkd.in/eyhJpnmq