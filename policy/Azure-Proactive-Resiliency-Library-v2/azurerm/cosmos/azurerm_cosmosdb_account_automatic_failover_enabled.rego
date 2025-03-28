package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource) if {
    resource.values.automatic_failover_enabled == true
}

deny_azurerm_configure_cosmosdb_account_automatic_failover_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/azurerm_configure_cosmosdb_account_automatic_failover_enabled: '%s' `azurerm_cosmosdb_account` must have automatic failover enabled for accounts with multi-write regions: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#enable-service-managed-failover-for-multi-region-accounts-with-single-write-region", [resource.address])
}