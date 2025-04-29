package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_configure_cosmosdb_account_enable_automatic_failover(resource) if {
    resource.values.body.properties.enableAutomaticFailover == true
}

deny_configure_cosmosdb_account_enable_automatic_failover contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DocumentDB/databaseAccounts")
    not valid_azapi_configure_cosmosdb_account_enable_automatic_failover(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/configure_cosmosdb_account_enable_automatic_failover: '%s' `azapi_resource` must have automatic failover enabled for accounts with multi-write regions: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#enable-service-managed-failover-for-multi-region-accounts-with-single-write-region", [resource.address])
}