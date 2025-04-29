package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource) if {
    resource.values.automatic_failover_enabled == true
}

valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource) if {
    resource.values.multiple_write_locations_enabled == true
}

valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource) if {
    count(resource.values.geo_location) <= 1
}

deny_configure_cosmosdb_account_enable_automatic_failover contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_configure_cosmosdb_account_automatic_failover_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/configure_cosmosdb_account_enable_automatic_failover: '%s' `azurerm_cosmosdb_account` must have automatic failover enabled for accounts with multi-write regions: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#enable-service-managed-failover-for-multi-region-accounts-with-single-write-region", [resource.address])
}