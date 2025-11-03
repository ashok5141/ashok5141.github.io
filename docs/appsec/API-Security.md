# API Security
- APIs is Application Programming Interface
- HackerOne Hacktivity for APIs [Link](https://hackerone.com/hacktivity/overview?queryString=api+AND+disclosed%3Atrue&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageIndex=0)

## Introduction
- Purpose and Importance of Securing APIs
    - Since APIs acts as a gateway between different applications and systems, they are prime targets for cyberattacks. 
    - Failure to adequately secure APIs can lead to various risks.
        - Data Breaches
        - Identity and Authentication Attacks
        - DoS, DDoS and MiTM Attacks
        - API Abuse

## Deep Dive in APIs
- GRAPHQL, SOAP, REST

##### REST API
- REST (Representational State Transfer) is an architectural style for designning networked applications, and it is widely used for building APIs.
- RESTful APIs  are based on a set of constraints that leverage HTTP methods and status codes for communication between clients and servers.
- REST APIs use simple and intuitive URLs to represent resources, and they support various data formats like JSON and XML.
![REST APIs](/assets/RESTAPIs.jpg)

##### SOAP API
- SOAP (Simple Object Access Protocol) is a protocol for exchanging structured information in the implementation of web services.
- It uses XML to define the message format and relies on HTTP, SMTP, TCP and other transport protocols for message delivery.
- SOAP APIs are considered more rigid and complex compared to REST APIs due to their reliance on XML and a set of strict standards.
![SOAP APIs](/assets/SOAPAPIs.png)

##### GRAPHQL
- GraphQL is a query language for APIs developed by Facebook.
- Unlike REST and SOAP, GraphQL allows clients to request only the specific data they need, making it more flexiable and efficient in data retrieval.
- With GraphQL, clients can define the shape of the data they want, and the server responds with the exact data in a single request.
![GraphQL](/assets/GraphQL.jpg)

| REST | SOAP | GRAPHQL |
|:- | :- | :- |
| Social Media APIs: Facebook, Twitter and Instagram | Enterprice Web Service: News aggregators, blogging platforms, and content-heavy websites | Content-Rich Applications: News aggregators, blogging platforms, and content-heavy websites |
| E-Commerce APIs: APIs for online marketplaces like Amazon and eBay | Financial Services: Transactions, account management, and data retrieval | Personalized Experiences: E-commerce platforms |
| IoT APIs: Control smart devies, such as thermostats, smart home assistants, and wearables | Government Services: Tax filing, social security benefits, and online permit application. | Data Aggregation: E-Commerce product catalog | 