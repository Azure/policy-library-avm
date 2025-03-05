package checkov

import rego.v1

valid_azapi_postgresql_server_infrastructure_encryption_enabled(resource) if {
    resource.change.after.body.properties.infrastructureEncryption == "Enabled"
}

deny_CKV_AZURE_130_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.address == "azurerm_postgresql_server.example"
    not valid_azapi_postgresql_server_infrastructure_encryption_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_130: Ensure that PostgreSQL server enables infrastructure encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLEncryptionEnabled.py")
}
