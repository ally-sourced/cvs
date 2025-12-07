# PowerShell script to review Azure SQL configurations and list only those failing security controls

# Ensure login
az login

# Output directory for results
$output_dir = ".\AzureSQLReview"
New-Item -ItemType Directory -Force -Path $output_dir

# Get all subscriptions
$subscriptions = az account list --query "[].{name:name, id:id}" -o json | ConvertFrom-Json

# Initialize an output result for failing databases
$failures = @()
$i = 0
# Iterate through subscriptions
foreach ($subscription in $subscriptions) {
    $subscription_name = $subscription.name
    $subscription_id = $subscription.id
    $i ++
    Write-Host $i

    # Set subscription context
    az account set --subscription "$subscription_id"

    # Get SQL servers in the current subscription
    $sql_servers = az sql server list --query "[].{name:name, resourceGroup:resourceGroup}" -o json | ConvertFrom-Json

    foreach ($server in $sql_servers) {
        $server_name = $server.name
        $resource_group = $server.resourceGroup
        Write-Host "$subscription_name --> " + "$resource_group --> " + "$server_name"
        if (-not $resource_group) {
            Write-Host "Warning: Resource group for server $server_name not found."
            continue
        }

        # Get databases in the current SQL server
        $sql_databases = az sql db list --server "$server_name" --resource-group "$resource_group" --query "[].{name:name}" -o json | ConvertFrom-Json

        foreach ($db in $sql_databases) {
            $db_name = $db.name
            
            # Initialize a list of failed controls
            $failed_controls = @()

            # Authentication and Access Control
            $aad_auth = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "identity" -o json
            if (-not $aad_auth) {
                $failed_controls += "Azure Active Directory not integrated"
            }

            # Check the users and their roles (example logic)
            $users = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "userName" -o json
            # Check for excessive privileges (assuming we have a predefined check)
            if ($users -contains "admin") {
                $failed_controls += "User has excessive privileges"
            }

            # Network Security
            $firewalls = az sql server firewall-rule list --resource-group "$resource_group" --server "$server_name" -o json
            if (-not $firewalls) {
                $failed_controls += "No firewall rules configured"
            }

            # Data Protection
            $tde_status = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "transparentDataEncryption.status" -o json
            if ($tde_status -ne "Enabled") {
                $failed_controls += "Transparent Data Encryption disabled"
            }
            
            # Check if any columns are encrypted (Always Encrypted)
            $encrypted_columns = az sql db show --name "$db_name" --server "$server_name" --resource-group "$resource_group" --query "encryptionProtector" -o json
            if (-not $encrypted_columns) {
                $failed_controls += "Always Encrypted not configured"
            }

            # Auditing and Monitoring
            $auditing = az sql db audit-policy show --name "$db_name" --server "$server_name" --resource-group "$resource_group" -o json
            if (-not $auditing) {
                $failed_controls += "Auditing not enabled"
            }

            # Only add the result if there are failed controls
            if ($failed_controls.Count -gt 0) {
                $result_entry = "$subscription_name,$resource_group,$server_name,$db_name,Failed Controls: $($failed_controls -join '; ')"
                $failures += $result_entry
            }
        }
    }
}

# Output results to a CSV file if there are failures
if ($failures.Count -gt 0) {
    $failures | Out-File -FilePath "$output_dir\SQL_Failed_Controls_Report.csv" -Force
    Write-Host "Review completed. Failed controls are saved in SQL_Failed_Controls_Report.csv in the AzureSQLReview directory."
} else {
    Write-Host "No failed controls found across all Azure SQL Databases."
}
