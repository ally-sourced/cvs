<#
PowerShell 5.1 compatible AKS admission/runtime assessment across ALL Azure subscriptions.

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
        $logs = $raw.logs
        if ([string]::IsNullOrWhiteSpace($logs)) { return $null }

        # Strip warnings before JSON
        $firstBrace = $logs.IndexOf("{")
        $firstBracket = $logs.IndexOf("[")
        $startCandidates = @()
        if ($firstBrace -ge 0) { $startCandidates += $firstBrace }
        if ($firstBracket -ge 0) { $startCandidates += $firstBracket }
        if (-not $startCandidates -or $startCandidates.Count -eq 0) { return $null }

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

    try {
        $subAssignments = az policy assignment list --scope $SubscriptionScope -o json | ConvertFrom-Json
        if (-not $subAssignments) { $subAssignments = @() }
        elseif ($subAssignments -isnot [System.Collections.IEnumerable]) { $subAssignments = @($subAssignments) }
    } catch { $subAssignments = @() }

    try {
        $rgAssignments = az policy assignment list --scope $rgScope -o json | ConvertFrom-Json
        if (-not $rgAssignments) { $rgAssignments = @() }
        elseif ($rgAssignments -isnot [System.Collections.IEnumerable]) { $rgAssignments = @($rgAssignments) }
    } catch { $rgAssignments = @() }

    try {
        $aksAssignments = az policy assignment list --scope $ClusterResourceId -o json | ConvertFrom-Json
        if (-not $aksAssignments) { $aksAssignments = @() }
        elseif ($aksAssignments -isnot [System.Collections.IEnumerable]) { $aksAssignments = @($aksAssignments) }
    } catch { $aksAssignments = @() }

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

# ---- UPDATED: now null-tolerant and not Mandatory ----
function Extract-ConstraintAssignmentMap {
    param([Parameter(Mandatory=$false)]$ConstraintsJson)

    $map = New-Object System.Collections.Generic.List[object]
    if ($null -eq $ConstraintsJson) { return $map }
    if (-not $ConstraintsJson.items) { return $map }

    foreach ($c in $ConstraintsJson.items) {
        $kind = $c.kind
        $name = $c.metadata.name
        $ns   = $c.metadata.namespace

        $ann = $c.metadata.annotations
        $assignmentIds = @()
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

    $cpCount = 0
    $pCount  = 0
    if ($clusterPolicies -and $clusterPolicies.items) { $cpCount = $clusterPolicies.items.Count }
    if ($policies -and $policies.items) { $pCount = $policies.items.Count }

    $kyvernoPodNames = @()
    if ($kyvernoPods -and $kyvernoPods.items) { $kyvernoPodNames = $kyvernoPods.items.metadata.name }

    $cpNames = @()
    if ($clusterPolicies -and $clusterPolicies.items) { $cpNames = $clusterPolicies.items.metadata.name }

    $acrSignals = @()
    $imagePolicyHints = @()

    if ($clusterPolicies -and $clusterPolicies.items) {
        foreach ($item in $clusterPolicies.items) {
            $pname = $item.metadata.name
            $txt = ""
            try { $txt = ($item | ConvertTo-Json -Depth 70) } catch { $txt = "" }

            if ($txt -match "verifyImages") { $imagePolicyHints += ("verifyImages:" + $pname) }
            if ($txt -match "image" -and $txt -match "registry|registries|allowed|deny|block|restrict") {
                $imagePolicyHints += ("image_validate:" + $pname)
            }
            if ($txt -match "\*\.azurecr\.io" -or $txt -match "azurecr\.io") { $acrSignals += ("kyverno_mentions_azurecr_io:" + $pname) }
        }
    }

    $installed = $false
    if ($kyvernoNs -ne $null) { $installed = $true }
    if (-not $installed -and $kyvernoPods -and $kyvernoPods.items -and $kyvernoPods.items.Count -gt 0) { $installed = $true }
    if (-not $installed -and $cpCount -gt 0) { $installed = $true }
    if (-not $installed -and $pCount -gt 0) { $installed = $true }

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

# ---------- Flattened summary helpers ----------
function To-FlatString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return "$Value" }
    if ($Value -is [datetime]) { return $Value.ToString("o") }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($i in $Value) {
            if ($null -ne $i -and "$i" -ne "") { $items += "$i" }
        }
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

    $summary = [PSCustomObject]@{
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

        securityProfileRawJson = To-FlatString $arm.securityProfileRawJson

        policyAssignments_SubscriptionCount  = To-FlatString $CsvRow.PolicyAssignments_SubscriptionCount
        policyAssignments_ResourceGroupCount = To-FlatString $CsvRow.PolicyAssignments_ResourceGroupCount
        policyAssignments_ClusterCount       = To-FlatString $CsvRow.PolicyAssignments_ClusterCount

        evidenceFilePath        = To-FlatString $CsvRow.EvidenceFilePath
        evidenceSummaryFilePath = ""
    }

    return $summary
}

# -------- Main --------
$results = New-Object System.Collections.Generic.List[object]

Write-Host "Discovering subscriptions..."
$subs = az account list -o json | ConvertFrom-Json
if (-not $subs) { throw "No subscriptions returned. Run: az login" }

$subIndex = 0
foreach ($sub in $subs) {
    $subIndex++
    $subId = $sub.id
    $subName = $sub.name
    $subScope = "/subscriptions/$subId"

    Write-Progress -Activity "AKS Admission/Runtime Assessment" -Status ("Subscription {0}/{1}: {2}" -f $subIndex, $subs.Count, $subName) -PercentComplete ([int](($subIndex/$subs.Count)*100))
    Write-Host ""
    Write-Host ("=== Subscription: {0} ({1}) ===" -f $subName, $subId)

    # Defender pricing (subscription-level)
    $defenderPricing = @()
    $defenderK8sTier = $null
    $defenderAcrTier = $null
    try {
        $defenderPricing = az security pricing list --subscription $subId -o json | ConvertFrom-Json
        $k8s = $defenderPricing | Where-Object { $_.name -eq "KubernetesService" } | Select-Object -First 1
        $acr = $defenderPricing | Where-Object { $_.name -eq "ContainerRegistry" } | Select-Object -First 1
        $defenderK8sTier = $k8s.pricingTier
        $defenderAcrTier = $acr.pricingTier
        Write-Host ("Defender pricing: KubernetesService={0} ; ContainerRegistry={1}" -f $defenderK8sTier, $defenderAcrTier)
    } catch {
        Write-Warning ("Could not query Defender pricing in subscription {0}" -f $subId)
    }

    # AKS clusters
    $clusters = @()
    try {
        $clusters = az aks list --subscription $subId -o json | ConvertFrom-Json
    } catch {
        Write-Warning ("Failed to list AKS clusters in subscription {0}. Skipping subscription." -f $subId)
        continue
    }

    if (-not $clusters -or $clusters.Count -eq 0) {
        Write-Host "No AKS clusters found."
        continue
    }

    $clusterIndex = 0
    foreach ($c in $clusters) {
        $clusterIndex++
        $rg = $c.resourceGroup
        $name = $c.name
        $location = $c.location
        $k8sVersion = $c.kubernetesVersion

        Write-Progress -Activity ("Subscription: {0}" -f $subName) -Status ("Cluster {0}/{1}: {2}" -f $clusterIndex, $clusters.Count, $name) -PercentComplete ([int](($clusterIndex/$clusters.Count)*100))
        Write-Host ("-> Assessing AKS: {0} (RG: {1}, Region: {2}, K8s: {3})" -f $name, $rg, $location, $k8sVersion)

        $aks = $null
        try { $aks = az aks show --subscription $subId -g $rg -n $name -o json | ConvertFrom-Json } catch { Write-Warning ("az aks show failed for {0}." -f $name) }

        $clusterId = $null
        if ($aks -and $aks.id) { $clusterId = $aks.id }
        else { $clusterId = $c.id }

        $clusterEvidenceDir = Join-Path $EvidenceRoot ("{0}\{1}\{2}" -f $subId, $rg, $name)
        New-Item -ItemType Directory -Path $clusterEvidenceDir -Force | Out-Null
        $evidenceFile = Join-Path $clusterEvidenceDir "evidence.json"
        $evidenceSummaryFile = Join-Path $clusterEvidenceDir "evidence_summary.json"

        Write-Host "   [1/5] Azure Policy assignments..."
        $policyEvidence = Get-PolicyAssignmentsEvidence -SubscriptionId $subId -SubscriptionScope $subScope -ResourceGroup $rg -ClusterResourceId $clusterId

        Write-Host "   [2/5] ARM posture..."
        $azurePolicyAddonEnabled = $false
        $securityProfileRawJson = $null
        $defenderEnabledArm = $null
        $oidcEnabled = $null
        $workloadIdentityEnabled = $null
        $privateCluster = $null

        if ($aks) {
            try { $azurePolicyAddonEnabled = [bool]$aks.addonProfiles.azurepolicy.enabled } catch { $azurePolicyAddonEnabled = $false }
            try { $securityProfileRawJson = ($aks.securityProfile | ConvertTo-Json -Compress -Depth 20) } catch { $securityProfileRawJson = $null }
            try { $defenderEnabledArm = $aks.securityProfile.defender.securityMonitoring.enabled } catch { $defenderEnabledArm = $null }
            try { $oidcEnabled = $aks.oidcIssuerProfile.enabled } catch { $oidcEnabled = $null }
            try { $workloadIdentityEnabled = $aks.securityProfile.workloadIdentity.enabled } catch { $workloadIdentityEnabled = $null }
            try { $privateCluster = $aks.apiServerAccessProfile.enablePrivateCluster } catch { $privateCluster = $null }
        }

        Write-Host "   [3/5] In-cluster admission (Gatekeeper/webhooks/constraints/PSA)..."
        $gatekeeperPods      = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get pods -n gatekeeper-system -o json'
        $validatingWebhooks  = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get validatingwebhookconfigurations -o json'
        $mutatingWebhooks    = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get mutatingwebhookconfigurations -o json'
        $constraintTemplates = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get constrainttemplates.templates.gatekeeper.sh -o json'
        $constraintsAll      = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get constraints -o json'
        $namespaces          = Invoke-AksKubectlJson -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name -KubectlCommand 'get ns -o json'

        $inClusterOk = $false
        if ($validatingWebhooks -or $mutatingWebhooks -or $gatekeeperPods -or $namespaces -or $constraintsAll -or $constraintTemplates) { $inClusterOk = $true }

        $inClusterStatus = "FAILED_OR_NOT_AUTHORIZED"
        if ($inClusterOk) { $inClusterStatus = "OK" }

        $gatekeeperInstalled = $false
        $gatekeeperPodNames = @()
        if ($gatekeeperPods -and $gatekeeperPods.items) {
            $gatekeeperInstalled = $true
            $gatekeeperPodNames = $gatekeeperPods.items.metadata.name
        }

        $validatingWebhookCount  = 0
        $mutatingWebhookCount    = 0
        $constraintTemplateCount = 0
        $constraintsCount        = 0

        if ($validatingWebhooks -and $validatingWebhooks.items) { $validatingWebhookCount = $validatingWebhooks.items.Count }
        if ($mutatingWebhooks -and $mutatingWebhooks.items) { $mutatingWebhookCount = $mutatingWebhooks.items.Count }
        if ($constraintTemplates -and $constraintTemplates.items) { $constraintTemplateCount = $constraintTemplates.items.Count }
        if ($constraintsAll -and $constraintsAll.items) { $constraintsCount = $constraintsAll.items.Count }

        $webhookNamesSample = @()
        if ($validatingWebhooks -and $validatingWebhooks.items) { $webhookNamesSample += ($validatingWebhooks.items.metadata.name | Select-Object -First 10) }
        if ($mutatingWebhooks -and $mutatingWebhooks.items) { $webhookNamesSample += ($mutatingWebhooks.items.metadata.name | Select-Object -First 10) }

        # Azure Policy ↔ Gatekeeper mapping (NULL SAFE)
        $constraintAssignmentMap = Extract-ConstraintAssignmentMap -ConstraintsJson $constraintsAll
        $mappedConstraints = @($constraintAssignmentMap | Where-Object { $_.AssignmentIds -and $_.AssignmentIds.Count -gt 0 })

        # Trusted images + ACR-only signals
        $acrOnlyGatekeeperSignals = @()
        $trustedImageSignals = @()
        $constraintKinds = @()

        if ($constraintsAll -and $constraintsAll.items) {
            foreach ($item in $constraintsAll.items) {
                $ckind = $item.kind
                $cname = $item.metadata.name
                if ($ckind) { $constraintKinds += $ckind }

                if ($ckind -match 'AllowedRepos|AllowedImages|AllowedRegistries|K8sAllowedRepos|AllowedRegistry' -or
                    $cname -match 'allowed|trusted|registry|image|repo') {
                    $trustedImageSignals += ("{0}/{1}" -f $ckind, $cname)
                }

                $acrSignals = Find-AcrOnlySignalsInGatekeeperConstraint -ConstraintItem $item
                if ($acrSignals -and $acrSignals.Count -gt 0) {
                    $acrOnlyGatekeeperSignals += ("{0}/{1}:{2}" -f $ckind, $cname, ($acrSignals -join ","))
                }
            }
        }

        # PSA
        $psaEnforcedNamespaces = @()
        $psaLevels = @()
        if ($namespaces -and $namespaces.items) {
            foreach ($ns in $namespaces.items) {
                $labels = $ns.metadata.labels
                if ($labels) {
                    $enforce = $labels."pod-security.kubernetes.io/enforce"
                    if ($enforce) {
                        $psaEnforcedNamespaces += $ns.metadata.name
                        $psaLevels += $enforce
                    }
                }
            }
        }

        Write-Host "   [4/5] Kyverno detection..."
        $kyverno = Detect-Kyverno -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name

        Write-Host "   [5/5] Writing evidence..."
        $allAssignments = @($policyEvidence.SubscriptionAssignments + $policyEvidence.ResourceGroupAssignments + $policyEvidence.ClusterAssignments)
        $assignmentById = @{}
        foreach ($a in $allAssignments) {
            if ($null -eq $a) { continue }

            $id = $null
            try { $id = $a.id } catch { $id = $null }
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            $display = $null
            try { $display = $a.name } catch { $display = $null }

            $props = $null
            try { $props = $a.properties } catch { $props = $null }
            if ($props -ne $null) {
                $dn = $null
                try { $dn = $props.displayName } catch { $dn = $null }
                if (-not [string]::IsNullOrWhiteSpace($dn)) { $display = $dn }
            }

            $assignmentById[$id] = $display
        }

        $mappedAssignmentNames = @()
        foreach ($m in $mappedConstraints) {
            foreach ($aid in $m.AssignmentIds) {
                if ($assignmentById.ContainsKey($aid)) { $mappedAssignmentNames += $assignmentById[$aid] }
                else { $mappedAssignmentNames += ("UNRESOLVED:{0}" -f $aid) }
            }
        }

        $evidenceObject = [PSCustomObject]@{
            metadata = [PSCustomObject]@{
                generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
                tool = "Assess-AKS-AdmissionRuntime-AllSubs-PS51.ps1"
            }
            cluster = [PSCustomObject]@{
                subscriptionName = $subName
                subscriptionId   = $subId
                resourceGroup    = $rg
                name             = $name
                location         = $location
                kubernetesVersion = $k8sVersion
                resourceId       = $clusterId
            }
            findings = [PSCustomObject]@{
                inClusterQueryStatus = $inClusterStatus
                azurePolicyAddonEnabled = $azurePolicyAddonEnabled
                gatekeeperInstalled     = $gatekeeperInstalled
                kyvernoInstalled        = $kyverno.Installed
                trustedImageSignals_gatekeeper = ($trustedImageSignals | Select-Object -Unique)
                acrOnlySignals_gatekeeper      = ($acrOnlyGatekeeperSignals | Select-Object -Unique)
                acrOnlySignals_kyverno         = ($kyverno.AcrSignals | Select-Object -Unique)
                azurePolicyConstraintsWithAssignmentIdCount = $mappedConstraints.Count
                azurePolicyAssignmentNamesFromConstraints   = ($mappedAssignmentNames | Select-Object -Unique)
                psaEnforcedNamespaces = ($psaEnforcedNamespaces | Select-Object -Unique)
                psaLevelsObserved     = ($psaLevels | Select-Object -Unique)
                webhookCounts = [PSCustomObject]@{ validating = $validatingWebhookCount; mutating = $mutatingWebhookCount }
                constraintCounts = [PSCustomObject]@{ templates = $constraintTemplateCount; constraints = $constraintsCount }
                kyvernoCounts = [PSCustomObject]@{ clusterPolicies = $kyverno.ClusterPolicyCount; policies = $kyverno.PolicyCount }
            }
            evidence = [PSCustomObject]@{
                arm = [PSCustomObject]@{
                    aksShow = $aks
                    securityProfileRawJson = $securityProfileRawJson
                    defenderEnabledArmBestEffort = $defenderEnabledArm
                    oidcIssuerEnabled = $oidcEnabled
                    workloadIdentityEnabled = $workloadIdentityEnabled
                    privateCluster = $privateCluster
                }
                azurePolicy = [PSCustomObject]@{
                    policyAssignments = [PSCustomObject]@{
                        subscription  = $policyEvidence.SubscriptionAssignments
                        resourceGroup = $policyEvidence.ResourceGroupAssignments
                        cluster       = $policyEvidence.ClusterAssignments
                    }
                    imageTrustAssignmentHints = $policyEvidence.ImageTrustAssignmentHints
                    constraintAssignmentMap   = $constraintAssignmentMap
                }
                defender = [PSCustomObject]@{
                    pricingList = $defenderPricing
                    pricingTier = [PSCustomObject]@{
                        kubernetesService = $defenderK8sTier
                        containerRegistry = $defenderAcrTier
                    }
                }
                inCluster = [PSCustomObject]@{
                    gatekeeperPods      = $gatekeeperPods
                    validatingWebhooks  = $validatingWebhooks
                    mutatingWebhooks    = $mutatingWebhooks
                    constraintTemplates = $constraintTemplates
                    constraints         = $constraintsAll
                    namespaces          = $namespaces
                }
                kyverno = $kyverno.Evidence
            }
        }

        Write-JsonFile -Path $evidenceFile -Object $evidenceObject

        $row = [PSCustomObject]@{
            SubscriptionName                 = $subName
            SubscriptionId                   = $subId
            ResourceGroup                    = $rg
            ClusterName                      = $name
            Location                         = $location
            KubernetesVersion                = $k8sVersion
            ClusterResourceId                = $clusterId
            PolicyAssignments_SubscriptionCount  = @($policyEvidence.SubscriptionAssignments).Count
            PolicyAssignments_ResourceGroupCount = @($policyEvidence.ResourceGroupAssignments).Count
            PolicyAssignments_ClusterCount       = @($policyEvidence.ClusterAssignments).Count
            PolicyImageTrustAssignmentHints      = (Safe-Join -Items $policyEvidence.ImageTrustAssignmentHints)
            AzurePolicyAddonEnabled          = $azurePolicyAddonEnabled
            GatekeeperInstalled              = $gatekeeperInstalled
            GatekeeperPodNamesSample         = (Safe-Join -Items ($gatekeeperPodNames | Select-Object -First 10))
            KyvernoInstalled                 = $kyverno.Installed
            KyvernoPodNamesSample            = (Safe-Join -Items $kyverno.PodNamesSample)
            KyvernoClusterPolicyCount        = $kyverno.ClusterPolicyCount
            KyvernoPolicyCount               = $kyverno.PolicyCount
            KyvernoImagePolicyHints          = (Safe-Join -Items $kyverno.ImagePolicyHints)
            ValidatingWebhookCount           = $validatingWebhookCount
            MutatingWebhookCount             = $mutatingWebhookCount
            WebhookNamesSample               = (Safe-Join -Items $webhookNamesSample)
            ConstraintTemplateCount          = $constraintTemplateCount
            ConstraintsCount                 = $constraintsCount
            ConstraintKinds                  = (Safe-Join -Items $constraintKinds)
            TrustedImageConstraintSignals    = (Safe-Join -Items $trustedImageSignals)
            ACR_Only_Signals_Gatekeeper      = (Safe-Join -Items $acrOnlyGatekeeperSignals)
            ACR_Only_Signals_Kyverno         = (Safe-Join -Items $kyverno.AcrSignals)
            AzurePolicyConstraintsWithAssignmentIdCount = $mappedConstraints.Count
            AzurePolicyAssignmentNamesFromConstraints   = (Safe-Join -Items ($mappedAssignmentNames | Select-Object -Unique))
            PSAEnforcedNamespacesCount       = ($psaEnforcedNamespaces | Select-Object -Unique).Count
            PSALevelsObserved                = (Safe-Join -Items ($psaLevels | Select-Object -Unique))
            DefenderPricingTier_KubernetesService = $defenderK8sTier
            DefenderPricingTier_ContainerRegistry = $defenderAcrTier
            DefenderEnabledArmBestEffort          = $defenderEnabledArm
            PrivateCluster                   = $privateCluster
            OidcIssuerEnabled                = $oidcEnabled
            WorkloadIdentityEnabled          = $workloadIdentityEnabled
            InClusterQueryStatus             = $inClusterStatus
            EvidenceFilePath                 = $evidenceFile
            EvidenceSummaryFilePath          = ""
        }

        if ($GenerateEvidenceSummary) {
            $summaryObj = Flatten-EvidenceSummary -EvidenceObject $evidenceObject -CsvRow $row
            $summaryObj.evidenceSummaryFilePath = $evidenceSummaryFile
            Write-JsonFile -Path $evidenceSummaryFile -Object $summaryObj
            $row.EvidenceSummaryFilePath = $evidenceSummaryFile
        }

        $results.Add($row) | Out-Null

        Write-Host ("   Completed: {0} (InCluster={1}, Gatekeeper={2}, Kyverno={3})" -f $name, $inClusterStatus, $gatekeeperInstalled, $kyverno.Installed)
        Write-Host ("   Evidence: {0}" -f $evidenceFile)
        if ($GenerateEvidenceSummary) { Write-Host ("   Evidence summary: {0}" -f $evidenceSummaryFile) }
    }
}

$results | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

Write-Progress -Activity "AKS Admission/Runtime Assessment" -Completed -Status "Done"
Write-Host ""
Write-Host "Done."
Write-Host ("CSV: {0}" -f $OutCsv)
Write-Host ("Evidence root: {0}" -f $EvidenceRoot)
Write-Host "Per cluster: evidence.json + (optional) evidence_summary.json"
