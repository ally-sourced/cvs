Policy-as-Code (Azure Policy) Enforcement Model
Description
- Validate mandatory tagging (Owner, TTL, Cost Center, Purpose)
- Enforce NSG, firewall, and route restrictions
- Restrict public endpoints, public IP creation, insecure protocols
- Enforce encryption‑in‑transit and encryption‑at‑rest

Acceptance Criteria
- Mandatory tagging policies validated.
- Deny rules for insecure configurations enforced.
- Encryption-in-transit and at-rest validated via policy.
- Policy assignments aligned to ephemeral scopes.
- TTL cleanup automation policy hooks validated.

Tasks
- Build Azure Policy definitions for tags and restrictions.
- Create deny policies for insecure network endpoints.
- Enforce encryption baseline policies via Azure Policy.
- Implement TTL-driven cleanup hooks.
- Test policy assignments in an ephemeral test subscription.

Notes:
Policies must match Non‑Prod guardrails but support Ephemeral‑specific constraints (TTL, auto-cleanup hooks). 
