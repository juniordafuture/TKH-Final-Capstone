# Secure Automated Web Architecture

## Description

This project provisions a hardened, internet-facing web server on AWS entirely
through infrastructure-as-code. Terraform defines the network, firewall, and
compute layers, and a GitHub Actions pipeline runs tfsec against every push so
insecure configuration is caught before it can reach the cloud. Security posture
is enforced by the pipeline rather than by whoever remembers to check.

## Technologies Used

- **AWS** — VPC, subnet, internet gateway, route table, security group, EC2,
  CloudWatch Logs, KMS, IAM
- **Terraform** — infrastructure-as-code; all resources declared in HCL
- **GitHub Actions** — CI/CD quality gate triggered on every push to `main`
- **tfsec** — static analysis (SAST) for Terraform, run as a blocking build step
- **Amazon Linux 2023 / Apache httpd** — bootstrapped via `user_data` on boot

## Architecture

**The VPC** occupies `10.0.0.0/16` and is isolated by default. Nothing enters or
leaves without an explicit route.

**The subnet** is a single public subnet at `10.0.1.0/24`. It is public only
because an internet gateway is attached to the VPC and the subnet's route table
carries a `0.0.0.0/0` route to that gateway. Without the route-table association
the subnet would silently fall back to the VPC default table and have no path to
the internet at all.

**The security group** is where the lockdown lives, and it is deliberately
asymmetric:

- **Port 80** is open to `0.0.0.0/0` — this is a public web server, so that is
  the requirement rather than an oversight.
- **Port 22** is open to exactly one `/32`. SSH is never exposed to the
  internet. The `my_home_ip` variable has no default, so Terraform refuses to
  produce a plan until an address is supplied — an accidentally open SSH port is
  structurally impossible rather than a matter of remembering.
- **Egress** is unrestricted, which the bootstrap script needs to reach the
  Amazon Linux package repositories.

**Beyond the network layer:** IMDSv2 is required (`http_tokens = "required"`),
closing the SSRF-to-credential-theft path central to the 2019 Capital One
breach. The root volume is encrypted. VPC Flow Logs capture all traffic to
CloudWatch under a customer-managed KMS key with rotation enabled, retained 90
days. The AMI is resolved at plan time from SSM Parameter Store rather than
hardcoded, so the instance never launches from a stale, unpatched image.

## Security Pipeline

Every push to `main` runs tfsec as a blocking gate. `soft_fail` is deliberately
not passed to the action: its entrypoint tests that input with
`[ -n "$INPUT_SOFT_FAIL" ]`, which is true for *any* non-empty value — including
the string `"false"`. Passing `soft_fail: false` silently enables soft-fail and
turns the gate into a rubber stamp. This was caught by deliberately breaking the
build and confirming it went red.

Four findings are suppressed with written justification in `main.tf`: public
HTTP ingress, unrestricted egress, public IP assignment, and the CloudWatch
log-stream IAM wildcard. Each is a requirement of the architecture, not a defect.
The one genuine gap — missing VPC flow logs — was fixed rather than suppressed.

## Usage

```bash
echo 'my_home_ip = "YOUR.PUBLIC.IP/32"' > terraform.tfvars
terraform init
terraform validate
terraform apply
terraform destroy   # when finished
```
