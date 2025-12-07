# PowerShell script to review Azure SQL configuration

# Ensure login
az login

# Output directory for results
$output_dir = ".\AzureSQLReview"
New-Item -ItemType Directory -Force -Path $output_dir

# Get all subscriptions
$subscriptions = az account list --query "[].{name:name, id:id}" -o json | ConvertFrom-Json

# Iterate through subscriptions
foreach ($subscription in $subscriptions) {
    $subscription_name = $subscription.name
    $subscription_id = $subscription.id

    # Set subscription context
    az account set --subscription "$subscription_id"

    # Get SQL servers
    $sql_servers = az sql server list --query "[].{name:name, resourceGroup:resourceGroupName, adminLogin:administratorLogin}" -o json | ConvertFrom-Json

    foreach ($server in $sql_servers) {
        $server_name = $server.name
        $resource_group = $server.resourceGroup
        
        # Get databases
        $sql_databases = az sql db list --server "$server_name" --resource-group "$resource_group" --query "[].{name:name}" -o json | ConvertFrom-Json

        foreach ($db in $sql_databases) {
            $db_name = $db.name

            # Authentication and Access Control
            $aad_auth = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "identity" -o json
            $users = az sql db list-usages --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "[]"

            # Network Security
            $firewalls = az sql db show --resource-group "$resource_group" --server "$server_name" --name "$db_name" --query "firewallRules" -o json
            $vnet_service_endpoint = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "virtualNetworkRules" -o json

            # Data Protection
            $tde_status = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "transparentDataEncryption.status" -o json
            $always_encrypted = az sql db encryption show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "columnEncryption" -o json

            # Auditing and Monitoring
            $auditing = az sql db audit-policy list --name "$db_name" --server "$server_name" --resource-group "$resource_group" -o json

            # Append results to output files
            Add-Content -Path "$output_dir\$subscription_name_SQL_Report.csv" -Value "$subscription_name, $resource_group, $server_name, $db_name, AAD: $aad_auth, Users: $users, Firewalls: $firewalls, VNet: $vnet_service_endpoint, TDE: $tde_status, Always Encrypted: $always_encrypted, Auditing: $auditing"
        }
    }
}

Write-Host "Review completed. Results are saved in the AzureSQLReview directory."
