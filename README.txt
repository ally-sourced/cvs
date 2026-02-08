Secret & Credential Management Integration
Description: 
- Enforce use of Key Vault with RBAC‑based access
- Disallow static credentials
- Integrate rotation at TTL expiry
- Ensure automation pipelines never expose secrets in logs

Definition of done:
1. Acceptance Criteria:
- All secrets stored only in Azure Key Vault.
- Static credentials fully disallowed.
- Secret rotation tied to TTL expiry.
- Key Vault logs forwarded to SIEM.
- Pipeline integrations validated to ensure no credential leakage.

2. Tasks:
- Implement Key Vault usage patterns for ephemeral workloads.
- Define Key Vault rotation schedule aligned with TTL.
- Integrate Key Vault diagnostics with SIEM.
- Validate secrets are not stored in pipelines or logs.

Notes: Key Vault logging → Send to central SIEM workspace
