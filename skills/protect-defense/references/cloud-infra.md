# Cloud / infrastructure-as-code playbook

## Threats
Public buckets/databases, over-privileged IAM, secrets in state/vars/images, open admin ports, unencrypted data, no logging, container escape via privileged pods, CI/CD pipeline compromise (the new perimeter).

## Mandatory controls
1. **Identity**: least-privilege IAM roles per service; no long-lived access keys (use OIDC federation for CI: GitHub Actions → AWS/GCP/Azure); MFA for humans; no wildcard `"Action": "*"` / `"Resource": "*"` except break-glass.
2. **Network**: private subnets for data stores; security groups deny by default; admin access via SSM/IAP/Bastion — never `0.0.0.0/0` on 22/3389/DB ports; WAF in front of public endpoints.
3. **Data**: encryption at rest (KMS CMK for sensitive data) and in transit; S3/GCS/Blob public access blocked at account level; versioning + backups with retention; DB not publicly accessible.
4. **Secrets**: AWS Secrets Manager / SSM Parameter Store / GCP Secret Manager / Azure Key Vault / Vault; Terraform `sensitive = true`, remote state encrypted with restricted access; never secrets in `.tfvars` committed.
5. **Containers** (`templates/infra/Dockerfile.node`): minimal/distroless base pinned by digest, multi-stage builds, non-root user, read-only root filesystem, no secrets in layers, `HEALTHCHECK`, image scanning in CI.
6. **Kubernetes**: Pod Security Standards `restricted`; `securityContext` (`runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`); NetworkPolicies default-deny; resource limits; secrets via external secrets operator; RBAC least privilege; no `hostPath`/`hostNetwork`.
7. **Logging & detection**: CloudTrail/Activity Logs/Audit Logs on and immutable; GuardDuty / Security Command Center / Defender for Cloud; alerting on root/owner usage and IAM changes.
8. **CI/CD**: branch protection, required reviews, OIDC instead of static keys, least-privilege workflow permissions, pinned actions, environment protection rules for production deploys.

## Tooling
`checkov -d .`, `tfsec`/`trivy config .`, `kube-score`, `hadolint Dockerfile` — run if available; otherwise add to CI.

## Verification
- `terraform plan` shows no public exposure changes unintended; policy-as-code (OPA/Conftest) optional.
