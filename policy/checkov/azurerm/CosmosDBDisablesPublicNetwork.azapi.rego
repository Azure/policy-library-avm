package checkov

import rego.v1

valid_azurerm_cosmosdb_no_public_network(resource) if {
    resource.values.public_network_access_enabled == false
}

valid_azapi_cosmosdb_no_public_network(resource) if {
    resource.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_101 contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_no_public_network(resource)

    reason := sprintf("checkov/CKV_AZURE_101: Ensure that Azure Cosmos DB disables public network access '%s' `azurerm_cosmosdb_account` must have 'public_network_access_enabled' set to 'false': https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisablesPublicNetwork.py", [resource.address])
}

deny_CKV_AZURE_101 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DocumentDB/databaseAccounts/2024-08-15"
    not valid_azapi_cosmosdb_no_public_network(resource)

    reason := sprintf("checkov/CKV_AZURE_101: Ensure that Azure Cosmos DB disables public network access '%s' `azapi_resource` must have 'properties.publicNetworkAccess' set to 'Disabled': https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisablesPublicNetwork.py", [resource.address])
}
