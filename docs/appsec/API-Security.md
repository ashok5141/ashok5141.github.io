# API Security
- APIs is Application Programming Interface
- HackerOne Hacktivity for APIs [Link](https://hackerone.com/hacktivity/overview?queryString=api+AND+disclosed%3Atrue&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageIndex=0)


# 🗃️ Complete Guide to API Types

This table covers the most common API types, categorized by their underlying architecture/protocol and by their scope/audience.

---

### 1. API Types by Architectural Style/Protocol (How they Work)

| API Name / Protocol | Definition | Key Characteristics | Example |
| :--- | :--- | :--- | :--- |
| **REST** (Representational State Transfer) | The most common architectural style. Uses standard **HTTP methods** (GET, POST, PUT, DELETE) to manipulate **resources** via URLs. | **Stateless**, flexible data format (usually **JSON**), simple, and highly scalable. | `GET /api/v1/products/456` (Fetching a specific product) |
| **SOAP** (Simple Object Access Protocol) | A protocol standard that uses **XML** for message formatting and typically operates over HTTP, SMTP, or other protocols. | **Strictly structured**, features built-in security and transaction handling (ACID compliance). Often used in enterprise, finance, and healthcare systems. | A **Payment Gateway API** request to process a secure transaction with a formal XML envelope. |
| **GraphQL** | An API **query language** and server-side runtime that lets the client request **exactly the data they need** and nothing more. | Clients define the response structure, preventing **over-fetching** and **under-fetching**. Operates over a single endpoint. | A single query asking for a user's `name` and their five most recent `posts`' `titles`. |
| **gRPC** (Google Remote Procedure Call) | A modern, high-performance **RPC** (Remote Procedure Call) framework that uses **HTTP/2** and **Protocol Buffers** for data serialization. | Very **fast and efficient** communication, often used for internal microservices and high-throughput systems. | A service call like `UserService.GetUser(user_id)` between two backend services. |
| **Webhook** | An **event-driven** API that allows one application to send **real-time notifications** to another when a specific event occurs. It's a "reverse API." | The server makes an HTTP POST request to a URL provided by the client (a callback URL). | A notification sent to an e-commerce platform when an **order is successfully processed** by the payment service. |
| **WebSocket** | A protocol providing **full-duplex** (two-way), persistent, and **real-time** communication over a single, long-lived TCP connection. | Ideal for continuous, low-latency data exchange, eliminating the need for constant polling. | The data feed for a **live stock ticker** or a **multiplayer online game**. |

---

### 2. API Types by Scope/Audience (Who can Use them)

| API Name / Scope | Definition | Audience | Example |
| :--- | :--- | :--- | :--- |
| **Public API** (Open API) | An API that is **openly available** to all external developers with minimal restrictions (sometimes requiring an API key). | The general public, external developers, and any third-party app. | The **Google Maps API** allowing a website to embed a map. |
| **Partner API** | An API shared **only with authorized external business partners** under a specific license or contract. | Specific, trusted third-party companies that have a business relationship with the host company. | An airline sharing its flight manifest API with an **online travel agency** (like Expedia or Priceline). |
| **Private API** (Internal API) | An API developed to be used **exclusively within an organization** to connect different internal systems and services. | Internal development teams and applications within the company's private network. | An internal API connecting a company's **HR database** to its **payroll system**. |
| **Composite API** | An API that bundles the requests for data or services from **multiple APIs** into a single, unified call. | Developers who need to perform complex operations that require data from several back-end services in one step. | An API call that simultaneously retrieves a customer's **profile**, their **order history**, and their **support tickets**. |

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