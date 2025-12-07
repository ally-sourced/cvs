# Ensure you are logged in and have the necessary permissions
az login

# Create output directory
$outputDir = ".\AzureSQLReview"
if (!(Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}

# Get all subscriptions
$subscriptions = az account list --query "[].{name:name, id:id}" -o json | ConvertFrom-Json

# Initialize control results hashtable
$controlResults = @{}

# Define control types
$controlTypes = @("Authentication and Access Control", "Network Security", "Data Protection", "Auditing and Monitoring", "Configuration Management")

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    $subscriptionName = $subscription.name
    $subscriptionId = $subscription.id

    # Set subscription context
    az account set --subscription $subscriptionId

    # Get SQL servers in the current subscription
    $sqlServers = az sql server list --query "[].{name:name, resourceGroup:resourceGroupName}" -o json | ConvertFrom-Json

    foreach ($server in $sqlServers) {
        $serverName = $server.name
        $resourceGroup = $server.resourceGroup
        
        # Check databases in the current SQL server
        $sqlDatabases = az sql db list --server $serverName --resource-group $resourceGroup --query "[].{name:name}" -o json | ConvertFrom-Json

        foreach ($db in $sqlDatabases) {
            $dbName = $db.name

            # Authentication and Access Control
            $aadAuth = az sql db show --name $dbName --server $serverName --resource-group $resourceGroup --query "identity" -o json
            $controlResults["Authentication and Access Control"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, AAD Integration: $aadAuth"

            # User and Role Management
            $users = az sql db list-usages --name $dbName --server $serverName --resource-group $resourceGroup --query "[]" -o json
            $controlResults["Authentication and Access Control"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, Users: $users"

            # Network Security
            $firewalls = az sql db show --resource-group $resourceGroup --server $serverName --name $dbName --query "firewallRules" -o json
            $controlResults["Network Security"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, Firewall Rules: $firewalls"

            $vnetServiceEndpoint = az sql db show --name $dbName --server $serverName --resource-group $resourceGroup --query "virtualNetworkRules" -o json
            $controlResults["Network Security"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, VNet Service Endpoint: $vnetServiceEndpoint"

            # Data Protection
            $tdeStatus = az sql db show --name $dbName --server $serverName --resource-group $resourceGroup --query "transparentDataEncryption.status" -o json
            $controlResults["Data Protection"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, TDE Status: $tdeStatus"

            $alwaysEncrypted = az sql db encryption show --name $dbName --server $serverName --resource-group $resourceGroup --query "columnEncryption" -o json
            $controlResults["Data Protection"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, Always Encrypted: $alwaysEncrypted"

            # Auditing and Monitoring
            $auditing = az sql db audit-policy list --name $dbName --server $serverName --resource-group $resourceGroup -o json
            $controlResults["Auditing and Monitoring"] += "$subscriptionName, $resourceGroup, $serverName, $dbName, Auditing: $auditing"

            # Advanced Threat Protection
            $threatProtection = az sql db threat-policy show --name $dbName --server $serverName --resource-group $resourceGroup -o json
            $controlResults["Auditing and Monitoring"] += "$subscriptionName, $resourceGroup, $serverName, $
