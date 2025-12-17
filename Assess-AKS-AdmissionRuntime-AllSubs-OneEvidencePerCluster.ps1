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

    # Strings are IEnumerable but we want count=1
    if ($Value -is [string]) { return 1 }

    # If it's a collection with Count, use it
    try {
        $c = $Value.Count
        if ($null -ne $c) { return [int]$c }
    } catch { }

    # If it's IEnumerable, enumerate
    if ($Value -is [System.Collections.IEnumerable]) {
        $n = 0
        foreach ($x in $Value) { $n++ }
        return $n
    }

    # Scalar object
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

        # Strip warnings before JSON
        $firstBrace = $logs.IndexOf("{")
        $firstBracket = $logs.IndexOf("[")
        $startCandidates = @()
        if ($firstBrace -ge 0) { $startCandidates += $firstBrace }
        if ($firstBracket -ge 0) { $startCandidates += $firstBracket }
        if (Get-Count $startCandidates -eq 0) { return $null }

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

    # Hints for image/registry-related policies (strict-mode safe)
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

    $cpCount = Get-Count $cpItems
    $pCount  = Get-Count $pItems

    $kyvernoPodNames = @()
    $podItems = $null
    try { $podItems = $kyvernoPods.items } catch { $podItems = $null }
    foreach ($pi in (As-Array $podItems)) {
        try { $kyvernoPodNames += $pi.metadata.name } catch { }
    }

    $cpNames = @()
    foreach ($cp in (As-Array $cpItems)) {
        try { $cpNames += $cp.metadata.name } catch { }
    }

    $acrSignals = @()
    $imagePolicyHints = @()

    foreach ($item in (As-Array $cpItems)) {
        if ($null -eq $item) { continue }
        $pname = $null
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
    if (-not $installed -and (Get-Count $podItems) -gt 0) { $installed = $true }
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

        securityProfileRawJson = To-FlatString $arm.securityProfileRawJson

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
if (Get-Count $subs -eq 0) { throw "No subscriptions returned. Run: az login" }

$subIndex = 0
foreach ($sub in $subs) {
    $subIndex++
    $subId = $null; $subName = $null
    try { $subId = $sub.id } catch { $subId = "" }
    try { $subName = $sub.name } catch { $subName = "" }
    $subScope = "/subscriptions/$subId"

    Write-Progress -Activity "AKS Admission/Runtime Assessment" -Status ("Subscription {0}/{1}: {2}" -f $subIndex, (Get-Count $subs), $subName) -PercentComplete ([int](($subIndex/(Get-Count $subs))*100))
    Write-Host ""
    Write-Host ("=== Subscription: {0} ({1}) ===" -f $subName, $subId)

    # Defender pricing (subscription-level)
    $defenderPricing = @()
    $defenderK8sTier = $null
    $defenderAcrTier = $null
    try {
        $defenderPricing = As-Array (az security pricing list --subscription $subId -o json | ConvertFrom-Json)
        $k8s = $defenderPricing | Where-Object { $_.name -eq "KubernetesService" } | Select-Object -First 1
        $acr = $defenderPricing | Where-Object { $_.name -eq "ContainerRegistry" } | Select-Object -First 1
        try { $defenderK8sTier = $k8s.pricingTier } catch { $defenderK8sTier = $null }
        try { $defenderAcrTier = $acr.pricingTier } catch { $defenderAcrTier = $null }
        Write-Host ("Defender pricing: KubernetesService={0} ; ContainerRegistry={1}" -f $defenderK8sTier, $defenderAcrTier)
    } catch {
        Write-Warning ("Could not query Defender pricing in subscription {0}" -f $subId)
    }

    # AKS clusters
    $clusters = @()
    try {
        $clusters = As-Array (az aks list --subscription $subId -o json | ConvertFrom-Json)
    } catch {
        Write-Warning ("Failed to list AKS clusters in subscription {0}. Skipping subscription." -f $subId)
        continue
    }

    if (Get-Count $clusters -eq 0) {
        Write-Host "No AKS clusters found."
        continue
    }

    $clusterIndex = 0
    foreach ($c in $clusters) {
        $clusterIndex++

        $rg = $null; $name = $null; $location = $null; $k8sVersion = $null
        try { $rg = $c.resourceGroup } catch { $rg = "" }
        try { $name = $c.name } catch { $name = "" }
        try { $location = $c.location } catch { $location = "" }
        try { $k8sVersion = $c.kubernetesVersion } catch { $k8sVersion = "" }

        Write-Progress -Activity ("Subscription: {0}" -f $subName) -Status ("Cluster {0}/{1}: {2}" -f $clusterIndex, (Get-Count $clusters), $name) -PercentComplete ([int](($clusterIndex/(Get-Count $clusters))*100))
        Write-Host ("-> Assessing AKS: {0} (RG: {1}, Region: {2}, K8s: {3})" -f $name, $rg, $location, $k8sVersion)

        $aks = $null
        try { $aks = az aks show --subscription $subId -g $rg -n $name -o json | ConvertFrom-Json } catch { Write-Warning ("az aks show failed for {0}." -f $name) }

        $clusterId = $null
        try { if ($aks -and $aks.id) { $clusterId = $aks.id } } catch { }
        if ([string]::IsNullOrWhiteSpace($clusterId)) {
            try { $clusterId = $c.id } catch { $clusterId = "" }
        }

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

        Write-Host "   [3/5] In-cluster admission..."
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
        $gkItems = $null
        try { $gkItems = $gatekeeperPods.items } catch { $gkItems = $null }
        if (Get-Count $gkItems -gt 0) {
            $gatekeeperInstalled = $true
            foreach ($pi in (As-Array $gkItems)) { try { $gatekeeperPodNames += $pi.metadata.name } catch { } }
        }

        $vwItems = $null; $mwItems = $null; $ctItems = $null; $conItems = $null
        try { $vwItems = $validatingWebhooks.items } catch { $vwItems = $null }
        try { $mwItems = $mutatingWebhooks.items } catch { $mwItems = $null }
        try { $ctItems = $constraintTemplates.items } catch { $ctItems = $null }
        try { $conItems = $constraintsAll.items } catch { $conItems = $null }

        $validatingWebhookCount  = Get-Count $vwItems
        $mutatingWebhookCount    = Get-Count $mwItems
        $constraintTemplateCount = Get-Count $ctItems
        $constraintsCount        = Get-Count $conItems

        $webhookNamesSample = @()
        foreach ($w in (As-Array $vwItems)) { try { $webhookNamesSample += $w.metadata.name } catch { } }
        foreach ($w in (As-Array $mwItems)) { try { $webhookNamesSample += $w.metadata.name } catch { } }
        $webhookNamesSample = $webhookNamesSample | Select-Object -First 10

        $constraintAssignmentMap = Extract-ConstraintAssignmentMap -ConstraintsJson $constraintsAll
        $mappedConstraints = @($constraintAssignmentMap | Where-Object { $_.AssignmentIds -and (Get-Count $_.AssignmentIds) -gt 0 })
        $mappedConstraintsCount = Get-Count $mappedConstraints

        $acrOnlyGatekeeperSignals = @()
        $trustedImageSignals = @()
        $constraintKinds = @()

        foreach ($item in (As-Array $conItems)) {
            if ($null -eq $item) { continue }
            $ckind = $null; $cname = $null
            try { $ckind = $item.kind } catch { $ckind = "" }
            try { $cname = $item.metadata.name } catch { $cname = "" }
            if (-not [string]::IsNullOrWhiteSpace($ckind)) { $constraintKinds += $ckind }

            if ($ckind -match 'AllowedRepos|AllowedImages|AllowedRegistries|K8sAllowedRepos|AllowedRegistry' -or
                $cname -match 'allowed|trusted|registry|image|repo') {
                $trustedImageSignals += ("{0}/{1}" -f $ckind, $cname)
            }

            $acrSignals = Find-AcrOnlySignalsInGatekeeperConstraint -ConstraintItem $item
            if ((Get-Count $acrSignals) -gt 0) {
                $acrOnlyGatekeeperSignals += ("{0}/{1}:{2}" -f $ckind, $cname, ((As-Array $acrSignals) -join ","))
            }
        }

        $psaEnforcedNamespaces = @()
        $psaLevels = @()
        $nsItems = $null
        try { $nsItems = $namespaces.items } catch { $nsItems = $null }
        foreach ($ns in (As-Array $nsItems)) {
            $labels = $null
            try { $labels = $ns.metadata.labels } catch { $labels = $null }
            if ($labels) {
                $enforce = $null
                try { $enforce = $labels."pod-security.kubernetes.io/enforce" } catch { $enforce = $null }
                if ($enforce) {
                    try { $psaEnforcedNamespaces += $ns.metadata.name } catch { }
                    $psaLevels += $enforce
                }
            }
        }

        Write-Host "   [4/5] Kyverno detection..."
        $kyverno = Detect-Kyverno -SubscriptionId $subId -ResourceGroup $rg -ClusterName $name

        Write-Host "   [5/5] Writing evidence..."
        $allAssignments = @($policyEvidence.SubscriptionAssignments + $policyEvidence.ResourceGroupAssignments + $policyEvidence.ClusterAssignments)
        $assignmentById = @{}
        foreach ($a in (As-Array $allAssignments)) {
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
        foreach ($m in (As-Array $mappedConstraints)) {
            foreach ($aid in (As-Array $m.AssignmentIds)) {
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
                azurePolicyConstraintsWithAssignmentIdCount = $mappedConstraintsCount
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

            PolicyAssignments_SubscriptionCount  = Get-Count $policyEvidence.SubscriptionAssignments
            PolicyAssignments_ResourceGroupCount = Get-Count $policyEvidence.ResourceGroupAssignments
            PolicyAssignments_ClusterCount       = Get-Count $policyEvidence.ClusterAssignments
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

            AzurePolicyConstraintsWithAssignmentIdCount = $mappedConstraintsCount
            AzurePolicyAssignmentNamesFromConstraints   = (Safe-Join -Items ($mappedAssignmentNames | Select-Object -Unique))

            PSAEnforcedNamespacesCount       = Get-Count ($psaEnforcedNamespaces | Select-Object -Unique)
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
