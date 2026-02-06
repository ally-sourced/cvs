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



Policy-as-Code (Azure Policy) — Enforcement Model for Ephemeral Non‑Prod POC Environments

Goal
Provide a repeatable, auditable Policy‑as‑Code model (Azure Policy + initiative) that enforces Non‑Prod guardrails in Ephemeral scopes while supporting TTL patterns and automated cleanup hooks.

Key Principles

Policy-as-Code: All policy definitions, initiatives, assignments, and parameter values are stored in source control (ARM/Bicep/Terraform/az cli templates).
Idempotence: Policies can be applied repeatedly without side effects; DeployIfNotExists is used for safe remediation.
Least‑Privilege & Safe‑Rollout: Audit mode → DeployIfNotExists → Deny. Test in Ephemeral test subscription before full deny.
Parameterization: Single definitions reused with different parameters for Non‑Prod vs Ephemeral (e.g., allowed SKUs, default TTL).
Observability: Compliance and remediation actions are logged and surfaced to dashboards and alerting.
Automation Hooks: TTL tags integrate with lifecycle automation (Logic Apps/Functions) via assigned remediation tasks or resource queries.
Enforcement Model Components

Policy Definitions (source-controlled)
Tagging:
require-tags-ephemeral (deny or modify)
validate-ttl-format (audit/deny)
append-default-tags (modify) — optional
Network & Exposure:
deny-public-ip-unless-approved (deny)
deny-internet-facing-nsg-rules (deny)
deny-application-gateway-public-exposure (deny/audit)
require-azure-firewall-or-nva-for-hub-egress (audit/deployIfNotExists)
Encryption:
require-storage-encryption (deny)
require-sql-encryption (deny)
require-tls-minimum-version (audit/deny)
require-disk-encryption (VM OS & data disks)
Monitoring:
deploy-diagnostics-to-loganalytics (deployIfNotExists)
require-monitoring-agent (deployIfNotExists)
Lifecycle/TTL:
require-ttl-tag-or-default (modify/deny)
TTL-remediation-hook (audit) — emits event to a remediation queue when ttl < threshold
SKU/Region controls:
deny-disallowed-regions (deny)
deny-disallowed-skus (deny)
Initiative (policySet) Composition
Ephemeral-NonProd-Initiative: includes above policies with parameters tuned for ephemeral constraints (shorter default TTL, limited allowed SKUs, stricter public exposure rules).
Versioned in repo; deployment creates/updates policy set.
Assignment Strategy
Stages:
Audit: assign initiative in AuditIfNotExists/Audit mode to Ephemeral test subscription.
Remediation: deploy DeployIfNotExists remediations for diagnostics/agent.
Prevent: switch tagging & exposure policies to Deny only after tests pass.
Scope:
Assign at management group for ephemeral environments or directly to Ephemeral subscriptions/RGs.
Use exclusion scopes for operations or emergency break‑glass accounts.
Remediation & Automation Hooks
DeployIfNotExists actions for diagnostics/agents run as managed remediation or deployment tasks.
TTL lifecycle:
Policy (audit) detects resources with ttl <= now OR missing ttl → writes event to an Azure Service Bus / Event Grid topic (via Activity Log or Azure Monitor alert) or tags resource with remediationNeeded=true.
Automation (Logic App / Function) consumes events/queries resources and executes remediation workflow (notify owner → snapshot → delete).
Assignment can create remediation tasks (policy remediation jobs) with a managed identity.
Testing & Validation
Test harness (ARM templates) creates:
resources missing required tags
resources creating public IPs
VMs without disk encryption / TLS < required
Verify policy evaluation state (non-compliant items) and remediation results.
Validate network connectivity exceptions with Network Team before denies.
CI/CD & Change Control
PR workflow: policy change → test plan → apply to Ephemeral test subscription → collect compliance metrics → promote to staging/prod initiative.
Use automated policy import and assignment via az cli / ARM / Bicep / Terraform in CD pipeline.
Acceptance Criteria Mapping (how model meets each)

Mandatory tagging policies validated:
require-tags-ephemeral in deny or modify mode; tested in Ephemeral test subscription; test cases in harness show denied creations when tags missing.
Deny rules for insecure configurations enforced:
deny-public-ip-unless-approved, deny-internet-facing-nsg-rules, deny-disallowed-skus/regions assigned and tested.
Encryption-in-transit and at-rest validated:
require-storage-encryption, require-sql-encryption, require-tls-minimum-version policies assigned; scans show non-compliant resources flagged; remediation where supported.
Policy assignments aligned to ephemeral scopes:
Initiative assigned to Ephemeral management group/subscriptions; parameterization shows TTL default values and owner contact details.
TTL cleanup automation policy hooks validated:
TTL policy (audit) triggers events or tags; automation runbook executes notify→snapshot→delete sequence in test scope.
Implementation Details / Example Patterns

Tagging policy (Prefer Modify then Deny):
modify-append-default-tags: effect = Modify; sets environment=ephemeral, owner=unknown, ttl=<now+72h> when missing.
require-tags: effect = Deny if owner or ttl missing or ttl invalid.
TTL validation: regex for ISO8601 UTC, or compare tag value via policy functions (DateTime comparison limited; use scheduled Logic App to evaluate expirations).
Public IP exceptions: allow when tag owner-approved=true and owner-approved-ttl >= now.
Encryption policies: leverage built-in Azure Policies:
Use built-in: "Require encryption at host for Virtual Machines", "Require secure transfer to storage accounts", "Audit SQL servers without TDE".
DeployIfNotExists examples:
deploy-diagnostics-to-loganalytics: parameters = workspaceId
enable-azure-monitor-agent: deploy extension via ARM template
Operational Considerations

Managed Identities: create a managed identity with Contributor on target scope for policy remediation deployments.
Remediation frequency: schedule remediation jobs to run nightly for DeployIfNotExists tasks if not immediate.
Exceptions/Break-glass: maintain an "ephemeral-exemptions" list via tag or assignment exclusion; require approvals recorded in ticketing system.
Alerts & Dashboards: ingest Azure Policy compliance into Log Analytics/Power BI; create an Ephemeral compliance dashboard with trend and drift info.
Tasks (mapped to deliverables & owners)

Build Azure Policy definitions for tags and restrictions — DevSecOps (owner)
Create deny policies for insecure network endpoints — Network + Security
Enforce encryption baseline policies via Azure Policy (use built-in where possible) — Security
Implement TTL-driven cleanup hooks (policy audit → Event Grid → LogicApp) — Platform Automation
Test policy assignments in an ephemeral test subscription — QA/Platform
Test Plan (brief)

Deploy initiative to Ephemeral test subscription in Audit mode.
Run test cases:
Create VM without tags → expect audit non-compliance; if modify policy present, tags appended.
Create Public IP → expect deny (or audit first).
Create storage account without secure transfer → expect non-compliant.
Create VM without disk encryption → expect non-compliant.
Enable DeployIfNotExists for diagnostics; create resources and confirm diagnostics are deployed to workspace.
Create resource with short TTL; ensure automation hook receives event and runs notify/snapshot/delete steps.
Deliverables

Repository with policy JSON/Bicep/ARM templates (versioned).
Initiative definition and assignment templates (ARM/Bicep).
Test harness ARM templates and test report.
Automation runbook/Logic App for TTL cleanup and remediation.
Compliance dashboard configuration and validation evidence.

Save the Bicep below as policies.ephemeral.bicep and run via az deployment or include in pipeline.

policies.ephemeral.bicep
param targetScope string                     // e.g. subscription resourceId or management group resourceId (/providers/...)
param logAnalyticsWorkspaceId string
param assignmentName string = 'Ephemeral-Guardrails-Assignment'
param exceptionTagName string = 'owner-approved'
param defaultTtlHours int = 72

// IDs/names
var policyName_appendTags = 'ephemeral-append-default-tags'
var policyName_requireTags = 'ephemeral-require-tags-deny'
var policyName_denyPublicIP = 'ephemeral-deny-publicip-unless-approved'
var policyName_ttlAudit = 'ephemeral-ttl-audit-hook'
var initiativeName = 'Ephemeral-NonProd-Initiative'

// 1) Modify policy: append default tags when missing
resource policyAppendTags 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName_appendTags
  properties: {
    displayName: 'Append default tags for Ephemeral resources'
    policyType: 'Custom'
    mode: 'All'
    description: 'Append environment, owner (unknown if missing), and ttl (now+default) when missing.'
    metadata: { category: 'Tags' }
    parameters: {
      defaultTtlHours: { type: 'Integer', metadata: { description: 'Default TTL hours to add when missing.' }, defaultValue: defaultTtlHours }
      defaultOwner: { type: 'String', defaultValue: 'unknown' }
      defaultEnvironment: { type: 'String', defaultValue: 'ephemeral' }
    }
    policyRule: {
      if: {
        anyOf: [
          { field: "tags['environment']", exists: 'false' },
          { field: "tags['owner']", exists: 'false' },
          { field: "tags['ttl']", exists: 'false' }
        ]
      }
      then: {
        effect: 'modify'
        details: {
          roleDefinitionIds: [
            '/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
          ]
          operations: [
            {
              // append environment if missing
              operation: 'addOrReplace'
              field: "tags['environment']"
              value: "[if(field('tags.environment'), field('tags.environment'), parameters('defaultEnvironment'))]"
            }
            {
              operation: 'addOrReplace'
              field: "tags['owner']"
              value: "[if(field('tags.owner'), field('tags.owner'), parameters('defaultOwner'))]"
            }
            {
              operation: 'addOrReplace'
              field: "tags['ttl']"
              // set TTL to now + defaultTtlHours in UTC ISO8601; Azure Policy cannot compute dates robustly, set placeholder sentinel to be handled by lifecycle automation
              value: "[if(field('tags.ttl'), field('tags.ttl'), concat('AUTO_TTL_', string(parameters('defaultTtlHours')), 'h'))]"
            }
          ]
        }
      }
    }
  }
}

// 2) Deny policy: require tags and TTL format (deny)
resource policyRequireTags 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName_requireTags
  properties: {
    displayName: 'Require tags: environment, owner, ttl (deny if missing or invalid)'
    policyType: 'Custom'
    mode: 'All'
    description: 'Deny resource creation when required tags are missing or ttl is not ISO8601/Z or missing after modify step.'
    metadata: { category: 'Tags' }
    policyRule: {
      if: {
        anyOf: [
          { field: "tags['environment']", exists: 'false' },
          { field: "tags['owner']", exists: 'false' },
          { field: "tags['ttl']", exists: 'false' },
          // Basic regex match for strict UTC ISO8601 ending with Z: YYYY-MM-DDThh:mm:ssZ
          {
            not: {
              field: "tags['ttl']",
              match: "^(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$"
            }
          },
          // deny sentinel placeholder
          { field: "tags['ttl']", like: 'AUTO_TTL_*' }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

// 3) Deny public IP creation unless approved tag present and true
resource policyDenyPublicIP 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName_denyPublicIP
  properties: {
    displayName: 'Deny Public IP creation unless exception tag present'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'Deny creation of Microsoft.Network/publicIPAddresses unless tags[exceptionTagName] == true'
    metadata: { category: 'Network' }
    parameters: {
      exceptionTagName: { type: 'String', metadata: { description: 'Tag name used to allow public IP creation.' }, defaultValue: exceptionTagName }
    }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Network/publicIPAddresses' },
          {
            anyOf: [
              { field: "[concat('tags[', parameters('exceptionTagName'), ']')]", exists: 'false' },
              { field: "[concat('tags[', parameters('exceptionTagName'), ']')]", notEquals: 'true' }
            ]
          }
        ]
      }
      then: { effect: 'deny' }
    }
  }
}

// 4) Audit TTL hook policy (audit resources missing valid ttl or with TTL approaching expiry)
// This policy is audit-only and will be used by automation to find resources requiring action.
resource policyTtlAudit 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName_ttlAudit
  properties: {
    displayName: 'Audit resources missing TTL or with TTL sentinel for automation'
    policyType: 'Custom'
    mode: 'All'
    description: 'Audit resources that have missing/invalid TTL or the AUTO_TTL sentinel for subsequent automated tagging/computation.'
    metadata: { category: 'Lifecycle' }
    policyRule: {
      if: {
        anyOf: [
          { field: "tags['ttl']", exists: 'false' },
          { field: "tags['ttl']", like: 'AUTO_TTL_*' },
          {
            not: {
              field: "tags['ttl']",
              match: "^(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$"
            }
          }
        ]
      }
      then: { effect: 'audit' }
    }
  }
}

// 5) Compose initiative (policy set)
resource policyInitiative 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = {
  name: initiativeName
  properties: {
    displayName: 'Ephemeral NonProd Guardrails Initiative'
    description: 'Policy set for ephemeral non-prod guardrails (tags, public IP deny, TTL audit, diagnostics left to assignment parameters).'
    metadata: { category: 'Ephemeral-NonProd' }
    policyDefinitions: [
      {
        policyDefinitionId: policyAppendTags.id
        parameters: {}
      }
      {
        policyDefinitionId: policyRequireTags.id
        parameters: {}
      }
      {
        policyDefinitionId: policyDenyPublicIP.id
        parameters: {
          exceptionTagName: { value: exceptionTagName }
        }
      }
      {
        policyDefinitionId: policyTtlAudit.id
        parameters: {}
      }
    ]
  }
}

// 6) Assign initiative to target scope
resource policyAssignment 'Microsoft.Authorization/policyAssignments@2021-06-01' = {
  name: assignmentName
  scope: targetScope
  properties: {
    displayName: '${assignmentName}'
    policyDefinitionId: policyInitiative.id
    description: 'Assign Ephemeral guardrails to target scope'
    metadata: {
      assignedBy: 'ephemeral-policy-cicd'
    }
    parameters: {}
  }
}

output initiativeId string = policyInitiative.id
output assignmentId string = policyAssignment.id

Notes:

Bicep cannot compute dynamic ISO8601 TTL times with current policy operations; the append-modify policy sets a sentinel "AUTO_TTL_" when TTL missing. Implement a small automation (Logic App/Function) that:
Enumerates resources with tag ttl like 'AUTO_TTL_*' or via policy audit results,
Replaces sentinel with computed ISO8601 expiry (UTC now + hours) and tags resource,
Or directly create TTL values on resource creation via provisioning pipeline.
Replace DeployIfNotExists diagnostic policies with the earlier provided template if you want automatic diagnostics deployment — add that policyDefinition and include in the initiative similarly.
Test in Audit mode first: change deny policies to Audit to observe impact.

Below are the requested artifacts:

Bicep snippet to add the DeployIfNotExists diagnostic policy definition and include it in your existing initiative.
An ARM template to deploy a Timer‑triggered Azure Function (PowerShell) that uses a System‑assigned Managed Identity to:
Query Azure Resource Graph for resources with tags like AUTO_TTL_*
Compute ISO8601 TTL (UTC now + hours)
Patch the resource tags with computed TTL
Example PowerShell function code to deploy into the Function App (zip deploy / Kudu).
Deploy flow recommended:

Deploy the Bicep (extend your policies.ephemeral.bicep) to add the diagnostics policy and include it in the initiative.
Deploy the Function App ARM template to your Ephemeral test subscription (function gets MSI and Role assignment to update tags and run Resource Graph).
Zip-deploy the PowerShell function code to the Function App (or use CI/CD).
Test in Audit mode, verify tags are updated, then promote deny policies.
Bicep snippet — add DeployIfNotExists diagnostic policy and include in initiative Add this into your existing policies.ephemeral.bicep (place near other policy definitions). It defines the diagnostics policy and adds it to the initiative.
@description('Resource ID of the Log Analytics workspace to receive diagnostics')
param logAnalyticsWorkspaceId string

var policyName_deployDiagnostics = 'ephemeral-deploy-diagnostics-to-workspace'

resource policyDeployDiagnostics 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyName_deployDiagnostics
  properties: {
    displayName: 'Deploy diagnostic settings to central Log Analytics workspace'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'Automatically deploy diagnostic settings for supported resource types to the specified Log Analytics workspace.'
    metadata: { category: 'Monitoring' }
    parameters: {
      logAnalytics: {
        type: 'String'
        metadata: { description: 'Resource ID of the Log Analytics workspace to receive diagnostics.' }
      }
      diagnosticSettingsName: {
        type: 'String'
        defaultValue: 'auto-diagnostics'
        metadata: { description: 'Name for the diagnostic settings resource.' }
      }
    }
    policyRule: {
      if: {
        field: 'type'
        in: [
          'Microsoft.Compute/virtualMachines'
          'Microsoft.Network/networkInterfaces'
          'Microsoft.Storage/storageAccounts'
          'Microsoft.Network/virtualNetworks'
          'Microsoft.Sql/servers/databases'
        ]
      }
      then: {
        effect: 'deployIfNotExists'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          roleDefinitionIds: [
            '/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa'
          ]
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  workspaceId: { type: 'string' }
                  diagnosticSettingsName: { type: 'string' }
                }
                resources: [
                  {
                    type: 'Microsoft.Insights/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: "[parameters('diagnosticSettingsName')]"
                    properties: {
                      workspaceId: "[parameters('workspaceId')]"
                      logs: [
                        { category: 'Administrative', enabled: true }
                        { category: 'Security', enabled: true }
                        { category: 'AuditEvent', enabled: true }
                        { category: 'Operational', enabled: true }
                      ]
                      metrics: [ { category: 'AllMetrics', enabled: true } ]
                    }
                  }
                ]
              }
              parameters: {
                workspaceId: { value: "[parameters('logAnalytics')]" }
                diagnosticSettingsName: { value: "[parameters('diagnosticSettingsName')]" }
              }
            }
          }
        }
      }
    }
  }
}

// Add this policy to the initiative composition (policyDefinitions array)
// Example: expand policyInitiative.properties.policyDefinitions with:
{
  policyDefinitionId: policyDeployDiagnostics.id
  parameters: {
    logAnalytics: { value: logAnalyticsWorkspaceId }
    diagnosticSettingsName: { value: 'auto-diagnostics' }
  }
}

Notes:

After adding the block above, rebuild/deploy the Bicep so the custom definition exists and the initiative references it.
When assigning the initiative, make sure the logAnalyticsWorkspaceId parameter is passed (your assignment parameters).
ARM template — Function App + Timer Trigger (PowerShell) to replace AUTO_TTL_* sentinel This template provisions:
Storage account for Function App
App Service plan (Consumption)
Function App (PowerShell) with SystemAssigned identity
Role assignment (Resource Graph Reader + contributor/Tag Contributor rights) to allow function to query resources and tag them
Save as function-ttl-automation.json and deploy to the Ephemeral test subscription/resource group.

Important: update parameter defaults (location, functionName, principalRoleAssignment scopes) as needed.

{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "location": { "type": "string", "defaultValue": "[resourceGroup().location]" },
    "functionName": { "type": "string", "defaultValue": "ttl-auto-updater" },
    "storageAccountName": { "type": "string", "defaultValue": "[concat('funcsa', uniqueString(resourceGroup().id))]" },
    "appServicePlanName": { "type": "string", "defaultValue": "[concat('asp-', uniqueString(resourceGroup().id))]" },
    "functionAppSku": { "type": "string", "defaultValue": "Y1" },
    "resourceGraphRoleScope": { "type": "string", "defaultValue": "/subscriptions/[subscription().subscriptionId]" },
    "tagContributorScope": { "type": "string", "defaultValue": "/subscriptions/[subscription().subscriptionId]" }
  },
  "variables": {
    "storageSku": "Standard_LRS",
    "siteName": "[parameters('functionName')]",
    "runtimeVersion": "~7"  // PowerShell 7
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2022-09-01",
      "name": "[parameters('storageAccountName')]",
      "location": "[parameters('location')]",
      "sku": { "name": "[variables('storageSku')]" },
      "kind": "StorageV2",
      "properties": { "supportsHttpsTrafficOnly": true }
    },
    {
      "type": "Microsoft.Web/serverfarms",
      "apiVersion": "2022-03-01",
      "name": "[parameters('appServicePlanName')]",
      "location": "[parameters('location')]",
      "sku": { "name": "[parameters('functionAppSku')]", "tier": "Dynamic" },
      "properties": { "reserved": true }
    },
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2022-03-01",
      "name": "[parameters('functionName')]",
      "location": "[parameters('location')]",
      "identity": { "type": "SystemAssigned" },
      "dependsOn": [
        "[resourceId('Microsoft.Web/serverfarms', parameters('appServicePlanName'))]",
        "[resourceId('Microsoft.Storage/storageAccounts', parameters('storageAccountName'))]"
      ],
      "properties": {
        "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', parameters('appServicePlanName'))]",
        "siteConfig": {
          "appSettings": [
            { "name": "AzureWebJobsStorage", "value": "[concat('DefaultEndpointsProtocol=https;AccountName=', parameters('storageAccountName'), ';AccountKey=', listKeys(resourceId('Microsoft.Storage/storageAccounts', parameters('storageAccountName')), '2022-09-01').keys[0].value)]" },
            { "name": "FUNCTIONS_WORKER_RUNTIME", "value": "powershell" },
            { "name": "WEBSITE_RUN_FROM_PACKAGE", "value": "1" },
            { "name": "WEBSITE_TIME_ZONE", "value": "UTC" }
          ]
        }
      }
    },
    // Role Assignment: Resource Graph query permission (Reader) for subscription (to run queries)
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "apiVersion": "2022-04-01",
      "name": "[guid(resourceId('Microsoft.Web/sites', parameters('functionName')), 'resource-graph-reader-role')]",
      "dependsOn": [ "[resourceId('Microsoft.Web/sites', parameters('functionName'))]" ],
      "properties": {
        "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions','acdd72a7-3385-48ef-bd42-f606fba81ae7')]", // Reader
        "principalId": "[reference(resourceId('Microsoft.Web/sites', parameters('functionName')), '2022-03-01', 'Full').identity.principalId]",
        "scope": "[parameters('resourceGraphRoleScope')]"
      }
    },
    // Role Assignment: Tag Contributor / Contributor to update resource tags (Resource Tag Contributor role)
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "apiVersion": "2022-04-01",
      "name": "[guid(resourceId('Microsoft.Web/sites', parameters('functionName')), 'tag-contributor-role')]",
      "dependsOn": [ "[resourceId('Microsoft.Web/sites', parameters('functionName'))]" ],
      "properties": {
        "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions','b24988ac-6180-42a0-ab88-20f7382dd24c')]", // Contributor (or use Tag Contributor custom role if available)
        "principalId": "[reference(resourceId('Microsoft.Web/sites', parameters('functionName')), '2022-03-01', 'Full').identity.principalId]",
        "scope": "[parameters('tagContributorScope')]"
      }
    }
  ],
  "outputs": {
    "functionAppName": { "type": "string", "value": "[parameters('functionName')]" },
    "principalId": { "type": "string", "value": "[reference(resourceId('Microsoft.Web/sites', parameters('functionName')), '2022-03-01', 'Full').identity.principalId]" }
  }
}

Notes for the Function App template:

The template grants Reader at subscription scope and Contributor at subscription scope to the Function MSI. Adjust to least privilege (Resource Graph Reader + Tag Contributor custom role scoped to target Ephemeral scopes).
If you have a "Tag Contributor" role definition, prefer assigning that instead of full Contributor.
PowerShell Function code (Timer trigger) — compute TTL and patch tags Save this as run.ps1 in your function folder (TimerTrigger). The function:
Runs every hour (CRON configured in function.json)
Uses Managed Identity to get access token for Resource Graph and ARM
Queries Resource Graph for resources with tags.ttl like 'AUTO_TTL_%' OR tags.ttl missing (adjust query)
Computes expiry as UTC now + hours from sentinel and updates the resource tags via PATCH
run.ps1:

Input bindings: none. Use TimerTrigger.
param($Timer)

Modules
Import-Module Az.Accounts -ErrorAction SilentlyContinue
Import-Module Az.Resources -ErrorAction SilentlyContinue

Acquire MSI token for Resource Graph and ARM
$resource = "https://management.azure.com/"
$tokenAuthUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([Uri]::EscapeDataString($resource))"
$tokenResponse = Invoke-RestMethod -Headers @{ "Metadata" = "true" } -Method GET -Uri $tokenAuthUrl
$token = $tokenResponse.access_token

Resource Graph query: find resources with tags.ttl like 'AUTO_TTL_%'
$graphUrl = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2018-09-01-preview"

Query to list resourceId and tags.ttl
$query = @{
  "query" = "Resources | where isnotempty(tags.ttl) | where tags.ttl startswith 'AUTO_TTL_' | project id, tags"
} | ConvertTo-Json
$rgResp = Invoke-RestMethod -Method POST -Uri $graphUrl -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } -Body $query
$results = $rgResp.data

if (-not $results) {
  Write-Output "No AUTO_TTL resources found."
  return
}

foreach ($item in $results) {
  $resourceId = $item.id
  $tags = $item.tags
  $ttlTag = $tags.ttl
  if ($ttlTag -and $ttlTag -match '^AUTO_TTL_(\d+)h$') {
    $hours = [int]$matches[1]
    $expiry = (Get-Date).ToUniversalTime().AddHours($hours).ToString("yyyy-MM-ddTHH:mm:ssZ")
    # Update tags: set ttl to expiry
    $tags.ttl = $expiry
    # Build patch body for tags
    $patchBody = @{ tags = $tags } | ConvertTo-Json -Depth 10
    $patchUrl = "https://management.azure.com$resourceId?api-version=2021-04-01"
    $patchResp = Invoke-RestMethod -Method PATCH -Uri $patchUrl -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } -Body $patchBody
    Write-Output "Patched $resourceId ttl -> $expiry"
  } else {
    Write-Output "Skipping resource $resourceId (ttl not AUTO_TTL pattern)"
  }
}

function.json for the Timer trigger (set schedule to run hourly):
{
  "bindings": [
    {
      "name": "Timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 * * * *"
    }
  ]
}

Deployment notes for function code:

Package function code (run.ps1 + function.json + host.json) into zip and deploy to the Function App via Zip Deploy: curl -X POST -u "$username:$password" --data-binary @function.zip "https://.scm.azurewebsites.net/api/zipdeploy" Use deployment credentials or set up GitHub Actions to do zip deploy.
Ensure the Function App's managed identity has:
Reader or Resource Graph Reader role to run Resource Graph queries
Tag Contributor (or Contributor) role scoped only to Ephemeral subscriptions/RGs to PATCH tags
Test plan (concise)
Deploy the updated Bicep with diagnostics policy to Ephemeral test MG/subscription in Audit mode.
Deploy Function App template to the test subscription resource group and assign minimal roles.
Create a test resource (e.g., VM) without TTL tag — the Append Modify policy should set AUTO_TTL_72h sentinel.
Wait for the Function (runs hourly) or trigger manually: confirm sentinel replaced with computed ISO8601 TTL tag.
Verify policy compliance view shows TTL tag now valid (regex match), and require-tags deny would allow resource only after TTL is valid.
After successful verification in Audit, switch require-tags policy from Audit to Deny and promote to enforcement.
Security & least-privilege guidance

Scope role assignments for the Function MSI to only the Ephemeral subscriptions/RGs.
Use a custom minimal role for tag updates rather than Contributor if possible (Tag Contributor role).
Use diagnostic workspace and central RBAC controls for logging/AAD auditing.
