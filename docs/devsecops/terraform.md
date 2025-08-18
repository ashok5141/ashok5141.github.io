---

### File: `docs/devsecops/terraform.md`

```markdown
---
layout: default
title: Security in Terraform
---
# Security in Terraform

Terraform is an Infrastructure as Code (IaC) tool. It can create and manage cloud resources, but it also needs to be secured to prevent misconfigurations.

## Security Practices

- **Static Analysis:** Using tools to check Terraform code for security misconfigurations before it's deployed.
- **State Management:** The Terraform state file can contain sensitive data. It must be stored securely, often in a remote, encrypted backend.
- **Least Privilege:** Configuring cloud resources with only the required permissions.

### Example: Resource Misconfiguration

The following code is a security misconfiguration because the S3 bucket is public, allowing anyone to access it.

```terraform
resource "aws_s3_bucket" "b" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
This should be changed to a private ACL like private in a real-world scenario.


---

### File: `docs/pen-test.md`

