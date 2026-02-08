Define the Identity & RBAC authorization model for Ephemeral Non‑Prod environments
Description
Service principals / managed identities only for deployments, updates, and resource lifecycle operations
RBAC scope applied at Subscription / RG level, depending on the final design (Story #2).
Aligning all assigned roles to Non‑Prod RBAC baseline, except human roles
TTL‑bound role assignments auto‑expire when the environment reaches its decommission date.
No human access workflows, no just‑in‑time elevation, no PIM.

Explicitly Out of Scope:
- Any form of human access (portal, PowerShell, CLI, click‑ops)
- Break‑glass access processes.
- New identity models beyond standard Non‑Prod patterns.

Dependencies
- Subscription/RG model
- Guardrails/Policies

Definition of done:

1. Acceptance Criteria:
- A complete RBAC matrix listing required automation roles, scopes, and mappings to Non Prod baselines is published
- Only service principals/managed identities can perform deployment actions; human access is technically blocked.
- TTL based auto expiry of identity assignments is implemented and validated.
- All pipelines (ExpressCloud/TAXI) are configured with proper privileges and least privilege scope
- Policies confirming no human access pass validation in test deployments.


2. Tasks:
- Inventory > align required RBAC roles with Non Prod equivalents
- Define a minimal custom role (if needed) for pipeline driven provisioning
- Document managed identity requirements for compute, networking, and infra modules
- Create TTL aware access expiration binding to the environment decommission workflow
- Validate pipeline operations against RBAC restrictions
- Publish Confluence design section

