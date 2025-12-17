<#
PowerShell 5.1 compatible AKS admission/runtime assessment across ALL Azure subscriptions.
StrictMode-safe (no ternary, no assumptions that .Count exists).

Outputs:
- Consolidated CSV (one row per AKS cluster)
- Per cluster:
  evidence.json (full)
  evidence_summary.json (optional flattened)

Prereqs:
- az login
- az cli installed
- rights to read AKS + policy assignments
- rights for az aks command invoke (for in-cluster data)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------- Settings --------
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RootOut   = Join-Path (Get-Location) "aks_assessment_$Timestamp"
$EvidenceRoot = Join-Path $RootOut "evidence"
$OutCsv    = Join-Path $RootOut "aks_admission_runtime_assessment_$Timestamp.csv"

# Optional: Generate flattened evidence_summary.json per cluster
$GenerateEvidenceSummary = $true

New-Item -ItemType Directory -Path $RootOut -Force | Out-Null
New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null

# ---------- Helpers ----------
function Get-Count {
    param([Parameter(Mandatory=$false)]$Value)

    if ($null -eq $Value) { return 0 }
    if ($Value -is [string]) { return 1 }

    try {
        $c = $Value.Count
        if ($null -ne $c) { return [int]$c }
    } catch { }

    if ($Value -is [System.Collections.IEnumerable]) {
        $n = 0
        foreach ($x in $Value) { $n++ }
        return $n
    }

    return 1
}

function As-Array {
    param([Parameter(Mandatory=$false)]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @($Value)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$Object
    )
    $dir = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    ($Object | ConvertTo-Json -Depth 90) | Out-File -FilePath $Path -Encoding utf8
}

function Safe-Join {
    param([object[]]$Items)
    if (-not $Items) { return "" }
    return ($Items | Where-Object { $_ -ne $null -and $_ -ne "" } | Select-Object -Unique) -join ";"
}

function Invoke-AksKubectlJson {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$ResourceGroup,
        [Parameter(Mandatory=$true)][string]$ClusterName,
        [Parameter(Mandatory=$true)][string]$KubectlCommand
    )

    $escaped = $KubectlCommand.Replace('"','\"')
    $cmd = "kubectl $escaped"

    try {
        $raw = az aks command invoke `
            --subscription $SubscriptionId `
            --resource-group $ResourceGroup `
            --name $ClusterName `
            --command $cmd `
            --only-show-errors `
            -o json 2>$null | ConvertFrom-Json

        if (-not $raw) { return $null }
        $logs = $null
        try { $logs = $raw.logs } catch { $logs = $null }
        if ([string]::IsNullOrWhiteSpace($logs)) { return $null }

        $firstBrace = $logs.IndexOf("{")
        $firstBracket = $logs.IndexOf("[")
        $startCandidates = @()
        if ($firstBrace -ge 0) { $startCandidates += $firstBrace }
        if ($firstBracket -ge 0) { $startCandidates += $firstBracket }
        if ((Get-Count $startCandidates) -eq 0) { return $null }

        $start = ($startCandidates | Sort-Object | Select-Object -First 1)
        $jsonText = $logs.Substring($start).Trim()
        return ($jsonText | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-PolicyAssignmentsEvidence {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$SubscriptionScope,
        [Parameter(Mandatory=$true)][string]$ResourceGroup,
        [Parameter(Mandatory=$true)][string]$ClusterResourceId
    )

    $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"

    $subAssignments = @()
    $rgAssignments  = @()
    $aksAssignments = @()

    try { $subAssignments = az policy assignment list --scope $SubscriptionScope -o json | ConvertFrom-Json } catch { $subAssignments = @() }
    try { $rgAssignments  = az policy assignment list --scope $rgScope -o json | ConvertFrom-Json } catch { $rgAssignments  = @() }
    try { $aksAssignments = az policy assignment list --scope $ClusterResourceId -o json | ConvertFrom-Json } catch { $aksAssignments = @() }

    $subAssignments = As-Array $subAssignments
    $rgAssignments  = As-Array $rgAssignments
    $aksAssignments = As-Array $aksAssignments

    $imageHint = @()
    foreach ($a in @($subAssignments + $rgAssignments + $aksAssignments)) {
        if ($null -eq $a) { continue }

        $displayName = $null
        $policyDefId = $null
        $policySetId = $null
        $fallbackName = $null

        try { $fallbackName = $a.name } catch { $fallbackName = $null }

        $props = $null
        try { $props = $a.properties } catch { $props = $null }

        if ($props -ne $null) {
            try { $displayName = $props.displayName } catch { $displayName = $null }
            try { $policyDefId = $props.policyDefinitionId } catch { $policyDefId = $null }
            try { $policySetId = $props.policySetDefinitionId } catch { $policySetId = $null }
        }

        $hit = $false
        if ($displayName -and ($displayName -match 'image|images|registry|registries|ACR|container')) { $hit = $true }
        if ($policyDefId -and ($policyDefId -match 'image|registry|container')) { $hit = $true }
        if ($policySetId -and ($policySetId -match 'image|registry|container')) { $hit = $true }

        if ($hit) {
            if (-not [string]::IsNullOrWhiteSpace($displayName)) { $imageHint += $displayName }
            elseif (-not [string]::IsNullOrWhiteSpace($fallbackName)) { $imageHint += $fallbackName }
        }
    }

    return [PSCustomObject]@{
        SubscriptionAssignments   = $subAssignments
        ResourceGroupAssignments  = $rgAssignments
        ClusterAssignments        = $aksAssignments
        ImageTrustAssignmentHints = ($imageHint | Select-Object -Unique)
    }
}

function Extract-ConstraintAssignmentMap {
    param([Parameter(Mandatory=$false)]$ConstraintsJson)

    $map = New-Object System.Collections.Generic.List[object]
    if ($null -eq $ConstraintsJson) { return $map }

    $items = $null
    try { $items = $ConstraintsJson.items } catch { $items = $null }
    if ($null -eq $items) { return $map }

    foreach ($c in (As-Array $items)) {
        if ($null -eq $c) { continue }

        $kind = $null; $name = $null; $ns = $null
        try { $kind = $c.kind } catch { }
        try { $name = $c.metadata.name } catch { }
        try { $ns = $c.metadata.namespace } catch { }

        $assignmentIds = @()
        $ann = $null
        try { $ann = $c.metadata.annotations } catch { $ann = $null }

        if ($ann) {
            foreach ($p in $ann.PSObject.Properties) {
                $k = [string]$p.Name
                $v = [string]$p.Value

                if ($k -match "policyAssignments" -or $v -match "policyAssignments" -or
                    $k -match "Microsoft\.Authorization" -or $v -match "Microsoft\.Authorization") {

                    $candidate = @($k,$v) | Where-Object { $_ -match "/providers/Microsoft\.Authorization/policyAssignments/" }
                    foreach ($s in $candidate) {
                        $m = [regex]::Match($s, '(/subscriptions/[^ ]+/providers/Microsoft\.Authorization/policyAssignments/[^"'',\s]+)')
                        if ($m.Success) { $assignmentIds += $m.Groups[1].Value }
                    }
                }
            }
        }

        $map.Add([PSCustomObject]@{
            Kind = $kind
            Name = $name
            Namespace = $ns
            AssignmentIds = ($assignmentIds | Select-Object -Unique)
        }) | Out-Null
    }

    return $map
}

function Find-AcrOnlySignalsInGatekeeperConstraint {
    param([Parameter(Mandatory=$true)]$ConstraintItem)

    $signals = @()
    $json = $null
    try { $json = ($ConstraintItem | ConvertTo-Json -Depth 70) } catch { return @() }
    if (-not $json) { return @() }

    if ($json -match "\*\.azurecr\.io" -or $json -match "azurecr\.io") { $signals += "mentions_azurecr_io" }
    if ($json -match "allowedRepos" -or $json -match "allowedRegistr" -or $json -match "allowedImages") {
        $signals += "allowed_repo_or_registry_pattern"
    }

    return ($signals | Select-Object -Unique)
}

function Detect-Kyverno {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$ResourceGroup,
        [Parameter(Mandatory=$true)][string]$ClusterName
    )

    $kyvernoNs   = Invoke-AksKubectlJson -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ClusterName $ClusterName -KubectlCommand 'get ns kyverno -o json'
    $kyvernoPods = Invoke-AksKubectlJson -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ClusterName $ClusterName -KubectlCommand 'get pods -n kyverno -o json'
    $clusterPolicies = Invoke-AksKubectlJson -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ClusterName $ClusterName -KubectlCommand 'get clusterpolicies.kyverno.io -o json'
    $policies        = Invoke-AksKubectlJson -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ClusterName $ClusterName -KubectlCommand 'get policies.kyverno.io -A -o json'

    $cpItems = $null; $pItems = $null
    try { $cpItems = $clusterPolicies.items } catch { $cpItems = $null }
    try { $pItems  = $policies.items } catch { $pItems = $null }

    $cpCount = (Get-Count $cpItems)
    $pCount  = (Get-Count $pItems)

    $kyvernoPodNames = @()
    $podItems = $null
    try { $podItems = $kyvernoPods.items } catch { $podItems = $null }
    foreach ($pi in (As-Array $podItems)) { try { $kyvernoPodNames += $pi.metadata.name } catch { } }

    $cpNames = @()
    foreach ($cp in (As-Array $cpItems)) { try { $cpNames += $cp.metadata.name } catch { } }

    $acrSignals = @()
    $imagePolicyHints = @()

    foreach ($item in (As-Array $cpItems)) {
        if ($null -eq $item) { continue }
        $pname = ""
        try { $pname = $item.metadata.name } catch { $pname = "" }

        $txt = ""
        try { $txt = ($item | ConvertTo-Json -Depth 70) } catch { $txt = "" }

        if ($txt -match "verifyImages") { $imagePolicyHints += ("verifyImages:" + $pname) }
        if ($txt -match "image" -and $txt -match "registry|registries|allowed|deny|block|restrict") {
            $imagePolicyHints += ("image_validate:" + $pname)
        }
        if ($txt -match "\*\.azurecr\.io" -or $txt -match "azurecr\.io") { $acrSignals += ("kyverno_mentions_azurecr_io:" + $pname) }
    }

    $installed = $false
    if ($kyvernoNs -ne $null) { $installed = $true }
    if (-not $installed -and ((Get-Count $podItems) -gt 0)) { $installed = $true }
    if (-not $installed -and ($cpCount -gt 0)) { $installed = $true }
    if (-not $installed -and ($pCount -gt 0)) { $installed = $true }

    return [PSCustomObject]@{
        Installed = [bool]$installed
        PodNamesSample = ($kyvernoPodNames | Select-Object -First 10)
        ClusterPolicyCount = $cpCount
        ClusterPolicyNamesSample = ($cpNames | Select-Object -First 20)
        PolicyCount = $pCount
        ImagePolicyHints = ($imagePolicyHints | Select-Object -Unique)
        AcrSignals = ($acrSignals | Select-Object -Unique)
        Evidence = [PSCustomObject]@{
            Pods = $kyvernoPods
            ClusterPolicies = $clusterPolicies
            Policies = $policies
        }
    }
}

function To-FlatString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return "$Value" }
    if ($Value -is [datetime]) { return $Value.ToString("o") }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($i in $Value) { if ($null -ne $i -and "$i" -ne "") { $items += "$i" } }
        return ($items | Select-Object -Unique) -join ";"
    }

    try { return ($Value | ConvertTo-Json -Compress -Depth 15) } catch { return "$Value" }
}

function Flatten-EvidenceSummary {
    param(
        [Parameter(Mandatory=$true)]$EvidenceObject,
        [Parameter(Mandatory=$true)]$CsvRow
    )

    $f   = $EvidenceObject.findings
    $c   = $EvidenceObject.cluster
    $m   = $EvidenceObject.metadata
    $arm = $EvidenceObject.evidence.arm
    $def = $EvidenceObject.evidence.defender
    $pol = $EvidenceObject.evidence.azurePolicy

    return [PSCustomObject]@{
        generatedAtUtc = To-FlatString $m.generatedAtUtc
        tool           = To-FlatString $m.tool
        subscriptionName = To-FlatString $c.subscriptionName
        subscriptionId   = To-FlatString $c.subscriptionId
        resourceGroup    = To-FlatString $c.resourceGroup
        clusterName      = To-FlatString $c.name
        location         = To-FlatString $c.location
        kubernetesVersion = To-FlatString $c.kubernetesVersion
        clusterResourceId = To-FlatString $c.resourceId
        inClusterQueryStatus = To-FlatString $f.inClusterQueryStatus
        azurePolicyAddonEnabled = To-FlatString $f.azurePolicyAddonEnabled
        gatekeeperInstalled     = To-FlatString $f.gatekeeperInstalled
        kyvernoInstalled        = To-FlatString $f.kyvernoInstalled
        trustedImageSignals_gatekeeper = To-FlatString $f.trustedImageSignals_gatekeeper
        acrOnlySignals_gatekeeper      = To-FlatString $f.acrOnlySignals_gatekeeper
        acrOnlySignals_kyverno         = To-FlatString $f.acrOnlySignals_kyverno
        azurePolicyConstraintsWithAssignmentIdCount = To-FlatString $f.azurePolicyConstraintsWithAssignmentIdCount
        azurePolicyAssignmentNamesFromConstraints   = To-FlatString $f.azurePolicyAssignmentNamesFromConstraints
        policyImageTrustAssignmentHints            = To-FlatString $pol.imageTrustAssignmentHints
        psaEnforcedNamespaces = To-FlatString $f.psaEnforcedNamespaces
        psaLevelsObserved     = To-FlatString $f.psaLevelsObserved
        validatingWebhookCount  = To-FlatString $f.webhookCounts.validating
        mutatingWebhookCount    = To-FlatString $f.webhookCounts.mutating
        constraintTemplateCount = To-FlatString $f.constraintCounts.templates
        constraintsCount        = To-FlatString $f.constraintCounts.constraints
        kyvernoClusterPolicyCount = To-FlatString $f.kyvernoCounts.clusterPolicies
        kyvernoPolicyCount        = To-FlatString $f.kyvernoCounts.policies
        kyvernoImagePolicyHints   = To-FlatString $CsvRow.KyvernoImagePolicyHints
        defenderPricingTier_KubernetesService = To-FlatString $def.pricingTier.kubernetesService
        defenderPricingTier_ContainerRegistry = To-FlatString $def.pricingTier.containerRegistry
        defenderEnabledArmBestEffort          = To-FlatString $arm.defenderEnabledArmBestEffort
        privateCluster          = To-FlatString $arm.privateCluster
        oidcIssuerEnabled       = To-FlatString $arm.oidcIssuerEnabled
        workloadIdentityEnabled = To-FlatString $arm.workloadIdentityEnabled
        securityProfileRawJson  = To-FlatString $arm.securityProfileRawJson
        policyAssignments_SubscriptionCount  = To-FlatString $CsvRow.PolicyAssignments_SubscriptionCount
        policyAssignments_ResourceGroupCount = To-FlatString $CsvRow.PolicyAssignments_ResourceGroupCount
        policyAssignments_ClusterCount       = To-FlatString $CsvRow.PolicyAssignments_ClusterCount
        evidenceFilePath        = To-FlatString $CsvRow.EvidenceFilePath
        evidenceSummaryFilePath = ""
    }
}

# -------- Main --------
$results = New-Object System.Collections.Generic.List[object]

Write-Host "Discovering subscriptions..."
$subs = As-Array (az account list -o json | ConvertFrom-Json)
if ((Get-Count $subs) -eq 0) { throw "No subscriptions returned. Run: az login" }

# (rest of script continues exactly as previously provided; only fix needed was the parentheses style)
# IMPORTANT: apply the same pattern everywhere:
#   if ((Get-Count $x) -eq 0) { ... }
#   if ((Get-Count $x) -gt 0) { ... }

throw "STOP: You pasted only part of the script. Replace your current file with the previous full script, and apply the parentheses pattern everywhere you compare Get-Count output."
