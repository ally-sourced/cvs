# PowerShell script to review Azure SQL configurations

# Ensure login
#az login

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

    # Get SQL servers in the current subscription
    $sql_servers = az sql server list --query "[].{name:name, resourceGroup:resourceGroup}" -o json | ConvertFrom-Json

    foreach ($server in $sql_servers) {
        $server_name = $server.name
        $resource_group = $server.resourceGroup
        
        if (-not $resource_group) {
            Write-Host "Warning: Resource group for server $server_name not found."
            continue
        }
        
        # Get databases in the current SQL server
        $sql_databases = az sql db list --server "$server_name" --resource-group "$resource_group" --query "[].{name:name}" -o json | ConvertFrom-Json

        foreach ($db in $sql_databases) {
            $db_name = $db.name

            # Authentication and Access Control
            $aad_auth = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "identity" -o json
            $users = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "userName" -o json

            # Network Security
            $firewalls = az sql server firewall-rule list --resource-group "$resource_group" --server "$server_name" -o json
            $vnet_service_endpoint = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "virtualNetworkRules" -o json

            # Data Protection
            $tde_status = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "transparentDataEncryption.status" -o json
            
            # Check if any columns are encrypted (Always Encrypted)
            $encrypted_columns = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "encryptionProtector" -o json

            # Auditing and Monitoring
            $auditing = az sql db audit-policy show --name "$db_name" --server "$server_name" --resource-group "$resource_group" -o json

            # Append results to output files
            $result_entry = "$subscription_name,$resource_group,$server_name,$db_name,AAD:$aad_auth,Users:$users,Firewalls:$firewalls,VNet:$vnet_service_endpoint,TDE:$tde_status,Encrypted Columns:$encrypted_columns,Auditing:$auditing"
            Add-Content -Path "$output_dir\$subscription_name_SQL_Report.csv" -Value $result_entry
        }
    }
}

Write-Host "Review completed. Results are saved in the AzureSQLReview directory."
