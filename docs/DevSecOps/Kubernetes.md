K8s Architecture

- Historically, software was designed and deployed directly onto Linux-based Operating Systems. However, this often led to 'dependency hell'—where code failed to run on different systems due to mismatched libraries or configurations. To solve this, Docker was introduced. Docker packages an application and all its dependencies into a single container, ensuring consistency across any environment.
- While Docker is excellent for running individual containers, it lacks built-in capabilities for high-level management, such as autoscaling, self-healing (restarting failed containers), and load balancing across multiple servers. This led to the rise of `Kubernetes (K8s)`, a container orchestration platform that automates the deployment, scaling, and management of containerized applications at scale.
    - Automatic container scheduling and scaling
    - Self-healing (auto-restart, replace, reschedule)
    - Load balancing and service discovery
    - Declarative configuration using `YAML` files
    - Rolling updates and rollbacks


![Kubernetes](https://kubernetes.io/images/docs/components-of-kubernetes.svg)
 


##### Kubernetes Componenets

![K8s Componenets](/assets/K8s_Components.png)

# Kubernetes Fundamentals - Module 1 Summary

## 1. Core Concepts
* **Kubernetes (K8s)**: An open-source container orchestration system written in Go for automating software deployment, scaling, and management.
* **YAML**: A human-readable data serialization format that uses indentation to define structure and is commonly used for declarative configuration files.
---
## 2. Control Plane (Master Node) Components
The Control Plane is responsible for making global decisions about the cluster and detecting/responding to events.

* **API Server (`kube-apiserver`)**: The central component that exposes a RESTful API, validates configuration data, and handles authentication/authorization.
* **Etcd**: A key-value database that stores the entire state, configuration, and persistent storage of all Kubernetes resources.
* **Kube Scheduler**: A component that monitors pending pods and assigns them to the best-fit nodes based on resource availability and policies.
* **Controller Manager (`kube-controller-manager`)**: Runs controllers that continuously reconcile the current cluster state with the desired state (e.g., node health, replica sets).
* **Cloud Controller Manager**: A cloud-specific component that abstracts cloud provider APIs to manage infrastructure-level resources like load balancers and volumes.
---
## 3. Worker Node (Data Plane) Components
The Data Plane is responsible for running workloads and managing the container lifecycle.

* **Kubelet**: The primary node agent that ensures containers are running in a Pod as expected and reports node status back to the API server.
* **Kube Proxy**: A network proxy that maintains network rules (iptables/IPVS) to enable service discovery and traffic routing to pod endpoints.
* **Container Runtime**: Software (e.g., containerd, CRI-O) responsible for pulling images and executing container processes on the node.
---
## 4. Resource & Logical Components
* **Pod**: The smallest deployable unit that encapsulates one or more containers sharing a single IP, hostname, and storage.
* **Containers**: Isolated, lightweight environments that encapsulate an application and its dependencies to run reliably across different environments.
* **Namespace**: Logical partitions within a cluster used to isolate resources and organize multi-tenancy environments (e.g., dev, test, prod).
* **Service**: An abstraction that provides stable network access and load balancing to a set of pods, supporting both internal and external communication.
* **Ingress**: An API object that manages external HTTP/S access to services via rules for hostnames, paths, and TLS termination.
* **Deployments**: A declarative object used to manage the lifecycle of stateless applications, ensuring desired replica counts and supporting rolling updates.
* **Replica Sets**: A controller that ensures a specified number of identical pod replicas are running at all times.
* **ConfigMap**: A key-value store for non-sensitive configuration data, allowing applications to be reconfigured without rebuilding images.
* **Secrets**: A secure object for storing sensitive data like passwords and tokens, supporting base64 encoding and RBAC-controlled access.
* **Volumes**: Provide persistent or shared storage that retains data beyond the container lifecycle.
* **RBAC (Role-Based Access Control)**: An authorization mechanism that restricts resource access based on identity and the principle of least privilege.


# Threat Model and Labs(Kubernetes Goat)

- K8s security is often explained via the 4C's model: Cloud, Cluster, Container and Code. A threat model identifies the `trust boundaries` between these layers. [K8s Security](https://github.com/cncf/financial-user-group)

![K8s Trust Boundary](https://raw.githubusercontent.com/cncf/financial-user-group/refs/heads/main/projects/k8s-threat-model/AttackTrees/images/trustboundaries.png)

### Part 1 - Basic Architecture & Threat Surface
- The Control Plane (The "Brain")
    - **API Server**: The gateway. If unauthenticated or misconfigured, an attacker has a direct path to cluster takeover.
    - **Etcd**: The database. If accessible, an attacker can steal all secrets and service account tokens.
    - **Scheduler/Controllers**: Can be manipulated to move malicious workloads or bypass security policies.
- The Worker Nodes (The "Execution")
    - **Kubelet**: The node agent. If it allows anonymous access, an attacker can execute commands in any pod on that node.
    - **Kube-Proxy**: Manages networking. Can be abused for lateral movement.
    - **Container Runtime (Docker/containerd)**: If escaped, the attacker gains control of the underlying host machine.

### Part 2 - Mapping Threat Models to Kubernetes Goat Scenarios

| STRIDE Category | K8s Component At Risk | Threat Description | Kubernetes Goat Scenario Mapping |
| :--- | :--- | :--- | :--- |
| **Information Disclosure** | Code / Git / Secrets | Sensitive data leaked in images or source code. | `Sensitive keys in codebases`, `Hidden in layers` |
| **Elevation of Privilege** | RBAC / Service Accounts | A low-privileged pod uses a token to gain admin rights. | `RBAC least privileges misconfiguration`, `Gaining environment info` |
| **Elevation of Privilege** | Container Runtime | Escaping the container to reach the host OS. | `Container escape to the host system`, `DIND exploitation` |
| **Tampering** | Image Registry | An attacker modifies a "trusted" image to include a backdoor. | `Attacking private registry` |
| **Spoofing / Lateral Movement** | Network / API | Using a pod to scan the internal network or spoof services. | `SSRF in K8s world`, `Kubernetes namespaces bypass` |
| **Denial of Service** | Resource Limits | One pod consumes all CPU/RAM, crashing other apps. | `DoS the Memory/CPU resources` |
| **Tampering** | K8s API / Config | Misconfigured ports allow direct access to apps. | `NodePort exposed services` |


### Part 3: The "Attacker's Path" (Background for all 22 Scenarios)
- To understand why the 22 scenarios exist, you must follow the typical Kubernetes Kill Chain:

    - **Initial Access**: Exploiting an application bug (like SSRF) or finding a leaked credential (Git keys).
    - **Discovery**: Looking at environment variables or querying the API server to see "where am I?"
    - **Lateral Movement**: Moving from one namespace to another because of weak network policies.
    - **Privilege Escalation**: Finding a Service Account token with cluster-admin rights.
    - **Persistence/Impact**: Deploying a crypto-miner or deleting the cluster database.



#### Core Trust Boundaries
* **External User -> API Server:** Protected by AuthN/AuthZ.
* **Pod -> API Server:** Protected by Service Account RBAC.
* **Container -> Host:** Protected by Cgroups, Namespaces, and Runtimes.
* **Pod -> Pod:** Protected by Network Policies.

The Threat Matrix (Summary of 22 Scenarios)

- A. Supply Chain & Image Security
    * **Scenarios:** *Sensitive keys in codebases, Hidden in layers, Attacking private registry.*
    * **Defense:** Scan images, use private registries, and never hardcode secrets.

- B. Access Control (RBAC)
    * **Scenarios:** *RBAC misconfiguration, Gaining environment info, Helm v2 Tiller.*
    * **Defense:** Follow the Principle of Least Privilege (PoLP).

- C. Runtime & Escape
    * **Scenarios:** *Container escape, DIND exploitation, Docker/K8s CIS benchmarks.*
    * **Defense:** Use Pod Security Admission, non-root users, and read-only file systems.

- D. Networking & Lateral Movement
    * **Scenarios:** *SSRF, Namespace bypass, NodePort exposure, Network Boundaries.*
    * **Defense:** Implement Network Policies and disable the "Automount Service Account Token" where not needed.

- E. Monitoring & Governance
    * **Scenarios:** *KubeAudit, Falco, Popeye, Kyverno, Cilium Tetragon.*
    * **Defense:** These are the TOOLS used to detect and prevent the threats mentioned above.