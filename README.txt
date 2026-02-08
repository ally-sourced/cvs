Design components

Identity fabric:
Azure AD tenant(s) as authoritative identity source.
Hybrid identity (Azure AD Connect) for on‑premises users if required.
Managed Identities (system/user‑assigned) and service principals for workloads and pipelines.
Authentication:
Enforce MFA for all human accounts (Conditional Access).
Strong FIDO2 or certificate‑based auth where applicable.
Enforce passwordless where possible.
Conditional Access & continuous evaluation:
Policies evaluating device compliance, location, risk score, user risk, application sensitivity.
Use Conditional Access Session Controls to limit session behavior (e.g., blocking download, require app‑enforced controls).
Authorization:
RBAC tied to identity; use groups for role assignment; prefer dynamic groups and role assignments via automation.
Policy as code for RBAC (ARM/Bicep/Terraform modules + CI validation).
Identity protection & monitoring:
Enable Azure AD Identity Protection (risk events), sign‑in logs, and privileged identity alerts.
Integrate identity logs into SIEM (Azure Sentinel/other).
No static credentials:
Ensure all secrets are in Key Vault; use managed identities for resource access.
Key design decisions:
Human vs non‑human: only humans get interactive capabilities. Ephemeral Non‑Prod may block humans (service principals only).
Least privilege and time‑bounded elevation for humans (PIM or Just‑In‑Time) — note: for environments that disallow PIM, enforce alternative review and TTL controls.
Implementation steps (identity)

Baseline (2–3 weeks)
Inventory identities (users, SAs, managed identities) and group mapping — Responsible: IAM Engineer, Cloud Security.
Harden auth (2–4 weeks)
Enforce MFA, enable passwordless pilots, deploy Conditional Access baseline policies — Responsible: IAM + SecOps.
Managed identity rollout (2–3 weeks)
Replace static credentials with managed identities for services & pipelines — Responsible: Platform/DevOps.
Authorization as code (3–4 weeks)
Implement RBAC modules and CI validation; dynamic group rules — Responsible: Cloud Platform, DevOps.
Monitoring & alerts (2 weeks)
Forward Azure AD logs to SIEM, configure identity anomaly alerts — Responsible: SecOps.
Controls to validate identity control plane

Acceptance evidence: Conditional Access policies covering MFA, device compliance; logs showing only managed identities used by pipelines; RBAC matrix published; identity risk events being detected and acted on.
Tests: simulated risky sign‑ins; attempt interactive access where blocked; pipeline run using managed identity.
Network micro‑segmentation — design & implementation Goal: Minimize blast radius and lateral movement via fine‑grained segmentation; enforce Zero‑Trust network policies between workloads.
Design components

Segmentation model:
Resource grouping by trust level (e.g., public, DMZ, app‑tier, data‑tier, management).
Use subscription/RG or network constructs (VNets + subnets) combined with NSGs and Azure Firewall/Application Gateway/WAF for controls.
East‑West controls:
NSGs for subnet/VM NIC level; Azure Firewall policies / network virtual appliances for more complex inspection and FQDN/URL filtering.
Micro‑segmentation primitives: NSGs + Application Security Groups (ASGs), service tags, workload‑specific allow lists.
Identity‑aware networking:
Integrate identity/context (Azure AD) with network enforcement where feasible (Azure AD Conditional Access for apps; Azure Firewall with IDPS where supported).
Zero Trust network policy enforcement points:
eBPF/host agents (for Kubernetes) or host WAFs for pod‑level segmentation.
For VMs: host‑based firewalls + NSGs.
Encryption & mutual TLS:
Enforce TLS everywhere; consider mTLS between services for strong mutual authentication.
Service mesh (for Kubernetes):
Istio/Linkerd with mutual TLS and policy enforcement for pod‑to‑pod traffic.
Implementation steps (network)

Architecture & mapping (2 weeks)
Map workloads to zones/tiers and define allowed flows — Responsible: Network Architect, Cloud Architect.
Baseline segmentation (3–4 weeks)
Implement subscription/RG-to-VNet mapping, subnets, NSGs, ASGs, Azure Firewall — Responsible: Network Engineers.
Micro‑segmentation enforcement (4–6 weeks)
Apply least‑privilege NSG/ASG rules; migrate to IP/port/ID based allowlists; enable Azure Firewall Threat Intel & IDPS — Responsible: Network + SecOps.
App/service mesh for K8s (optional, 3–6 weeks)
Deploy service mesh and policies for pod‑level mutual TLS and authorization — Responsible: Platform/K8s Team.
Validate (2 weeks)
Pen test lateral movement, simulate compromised workload; log telemetry to SIEM — Responsible: SecOps + Red Team.
Controls & validation

Acceptance evidence: flow matrix documenting approved flows; NSG/Firewall rules matching matrix; SIEM showing blocked lateral traffic attempts; mTLS certificates deployed between services where required.
Tests: attempt unauthorized east‑west connection (should be blocked); verify allowed flows succeed; measure micro‑segmentation policy coverage.
Pipelines: explicit verification & enforcement Goal: Ensure all automated pipelines (ExpressCloud/TAXI/others) execute with explicit identity, least privilege, and verification steps; pipelines must never bypass Zero Trust checks.
Design components

Pipeline identity model:
Each pipeline run uses a dedicated service principal or managed identity scoped to least privilege for the pipeline tasks.
No use of human credentials; enforce Service Principal cert/secret rotation and Key Vault retrieval.
Pipeline policy gates:
Pre‑deploy checks (policy as code): security scanner results, infra policy compliance, vulnerability thresholds.
Approval gates only for human reviewable non‑prod exceptions (logged and time bound).
Secrets handling:
Fetch secrets at runtime from Key Vault using managed identity; never write secrets to logs or artifact storage.
Artifact provenance & signing:
Sign build artifacts; validate signature in deployment pipeline to prevent tampering.
Pipeline runtime verification:
Enforce environment attestation (e.g., agent version, image hash) before deployment.
Pipeline telemetry:
Forward pipeline run logs and audit events to SIEM; include identity, scope, and actions.
Implementation steps (pipelines)

Inventory & map pipelines (1–2 weeks)
Identify all pipelines and required scopes — Responsible: DevOps Lead, Cloud Security.
Identity standardization (2–3 weeks)
Configure managed identities per pipeline; remove static PATs/secrets — Responsible: DevOps.
Policy-as-code integration (3–4 weeks)
Add policy checks to pipeline (OPA/Gatekeeper/Conftest/Azure Policy) — Responsible: DevSecOps.
Secrets & Key Vault integration (2 weeks)
Ensure runtime retrieval only; secret redaction in pipeline logs — Responsible: DevOps + Security.
Artifact signing & attestation (3–4 weeks)
Implement signing in build and signature verification in deploy — Responsible: DevOps.
Validation runs (2 weeks)
Execute deployments to test envs and demonstrate pipeline rejects non‑compliant artifacts — Responsible: DevSecOps + SecOps.
Controls & validation

Acceptance evidence: pipeline runs only via managed identities; policy checks fail when non‑compliant; no secrets in logs; signed artifacts enforced.
Tests: attempt deployment with a pipeline using elevated scope (should be denied); attempt to log secret value (should be redacted).
Design review with enterprise Zero‑Trust architects Process
Prepare design package: identity diagrams, RBAC matrix, network flow matrix, pipeline identity/config, Key Vault integration, logging/telemetry plan, threat model, test plan.
Workshops:
2 workshops: (1) architecture walkthrough, (2) validation & remediation plan.
Feedback & iterate: track findings, remediations, acceptance sign‑off.
Participants & responsibilities

Zero Trust Architects (enterprise) – Review & approval.
Cloud Security Officer – Lead design package.
Identity, Network, DevOps, SecOps leads – Present components.
Effort estimate: 2–3 weeks (prep + workshops + remediation).

Operationalization and continuous enforcement Operational model
Governance:
Zero‑Trust governance board meets monthly; approves exceptions with TTL.
Automation:
Policy as code (Terraform/ARM/Bicep + OPA/Conftest) enforced in CI.
Guardrails via Azure Policy with deny/audit effects for critical violations.
Monitoring & detection:
Central SIEM ingest: Azure AD, Key Vault, NSG flow logs, Azure Firewall logs, pipeline audit logs, K8s audit logs.
Create detection rules for: unusual identity use, cross‑subnet flows, pipeline anomalies, secret access spikes.
Incident response:
Playbooks for identity compromise, lateral movement, pipeline compromise (runbooks in Sentinel/Azure Logic Apps).
Access lifecycle:
Enforce TTL on non‑human role assignments; automatic revocation at decommission.
Human privileges via PIM/time‑bound approvals (where allowed).
Continuous validation:
Continuous Compliance scans (CIS/benchmarks), automated penetration tests (scheduled), and red team exercises.
Operational tasks & responsibilities (ongoing)

SecOps: monitor SIEM, triage alerts — ongoing FTE 1–2.
Cloud Platform: maintain IaC, policies as code — ongoing FTE 1–2.
DevOps: pipeline management and secrets hygiene — ongoing FTE 1.
Network: manage segmentation and firewall rules — ongoing FTE 1.
Zero‑Trust board: governance and exception approvals — part‑time CISO + architects.
Enforcement mechanisms (technical & process) Technical
Azure Policy: deny deployment if not compliant (e.g., Key Vault use, managed identity use, RBAC restrictions).
Resource Locks & Tagging: enforce environment tags and lifecycle; TTL tag used by automation to expire assignments.
Conditional Access & Baseline: block legacy auth and risky sign‑ins.
Network controls: NSG/Firewall deny by default, allowlist flows only.
Pipeline gates: policy check failure prevents promotion.
Logging enforced: all control plane logs shipped to SIEM and retention policies applied.
Process

Access requests follow documented workflow, reviewed by governance; exceptions must be time‑bound and logged.
Regular audits (quarterly) and quarterly tabletop incident exercises.
Change control: any change to segmentation, RBAC baselines, or pipeline identity requires peer review and signoff.
Metrics & acceptance mapping Map acceptance criteria to measurable checks:
Acceptance: Identity validated as primary control plane

Metrics: % of deployments using managed identities; number of human interactive logins to non‑prod blocked; Conditional Access coverage %
Target: 100% pipeline identity usage; 0 interactive human access to ephemeral non‑prod.
Acceptance: Network micro‑segmentation validated

Metrics: Flow matrix coverage %, blocked lateral attempts, NSG rule drift %
Target: All documented allowed flows enforced; successful lateral movement tests blocked.
Acceptance: Pipeline verification enforces Zero Trust

Metrics: % of pipelines with policy gates, % of builds signed, number of secrets in logs (0)
Target: 100% pipelines with gates; 0 secret leakage incidents.
Acceptance: Zero Trust architects approve final design

Deliverable: Signed architecture review document.
Validation & testing plan (detailed)
Unit tests: IaC plan validations, policy unit tests (Conftest/OPA).
Integration tests: pipeline runs on staging, verify Key Vault retrieval and no logs.
Security tests:
Vulnerability scans
Penetration tests focusing on lateral movement and identity abuse
Red team scenario: compromise a service principal and attempt lateral movement and exfiltration
Continuous tests: scheduled canary deployments to validate policy enforcement.
Audit: 3rd party Zero Trust architecture review and compliance audit.
