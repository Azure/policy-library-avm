package checkov

import rego.v1

valid_azurerm_mysql_server_infrastructure_encryption_enabled(resource) if {
    resource.values.infrastructure_encryption_enabled == true
}

valid_azapi_mysql_server_infrastructure_encryption_enabled(resource) if {
    resource.body.properties.dataEncryption.type == "SystemManaged"
}

deny_CKV_AZURE_96 contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_server_infrastructure_encryption_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_96: Ensure that MySQL server enables infrastructure encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLEncryptionEnaled.py")
}

deny_CKV_AZURE_96 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforMySQL/flexibleServers/2023-12-30"
    not valid_azapi_mysql_server_infrastructure_encryption_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_96: Ensure that MySQL server enables infrastructure encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLEncryptionEnaled.py")
}
