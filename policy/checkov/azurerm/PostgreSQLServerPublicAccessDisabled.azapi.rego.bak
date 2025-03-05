package checkov

import rego.v1

valid_azapi_postgresql_server_public_access_disabled(resource) if {
    resource.change.after.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_68_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.address == "azurerm_postgresql_server.example"
    not valid_azapi_postgresql_server_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_68: Ensure that PostgreSQL server disables public network access. Resource %s has public network access enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerPublicAccessDisabled.py", [resource.address])
}
