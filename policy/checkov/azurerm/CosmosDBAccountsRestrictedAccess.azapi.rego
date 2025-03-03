package checkov

import rego.v1

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    resource.values.public_network_access_enabled == false
}

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    resource.values.is_virtual_network_filter_enabled == true
    resource.values.virtual_network_rule[_]
}

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    resource.values.is_virtual_network_filter_enabled == true
    resource.values.ip_range_filter[_]
}

deny_CKV_AZURE_99 contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_account_restricted_access(resource)

    reason := sprintf("checkov/CKV_AZURE_99: Ensure Cosmos DB accounts have restricted access %s", [resource.address])
    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBAccountsRestrictedAccess.py", [reason])
}


valid_azapi_cosmosdb_account_restricted_access(resource) if {
    resource.body.properties.publicNetworkAccess == "Disabled"
}

valid_azapi_cosmosdb_account_restricted_access(resource) if {
    resource.body.properties.isVirtualNetworkFilterEnabled == true
    resource.body.properties.virtualNetworkRules[_]
}

valid_azapi_cosmosdb_account_restricted_access(resource) if {
    resource.body.properties.isVirtualNetworkFilterEnabled == true
    resource.body.properties.ipRules[_]
}

deny_CKV_AZURE_99_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DocumentDB/databaseAccounts/2024-08-15"
    not valid_azapi_cosmosdb_account_restricted_access(resource.changes.after)

    reason := sprintf("checkov/CKV_AZURE_99: Ensure Cosmos DB accounts have restricted access %s", [resource.address])
    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBAccountsRestrictedAccess.py", [reason])
}
