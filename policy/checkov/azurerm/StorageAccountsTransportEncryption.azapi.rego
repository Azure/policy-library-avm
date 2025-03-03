package checkov

import rego.v1

valid_azurerm_storage_account_https_traffic_only(resource) if {
    resource.values.enable_https_traffic_only == true
}

valid_azapi_storage_account_https_traffic_only(resource) if {
    resource.body.properties.supportsHttpsTrafficOnly == true
}

deny_CKV_AZURE_3 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_https_traffic_only(resource)

    reason := sprintf("checkov/CKV_AZURE_3: Ensure that 'Secure transfer required' is set to 'Enabled' for azurerm_storage_account %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountsTransportEncryption.py", [resource.address])
}

deny_CKV_AZURE_3_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/2023-05-01"
    not valid_azapi_storage_account_https_traffic_only(resource)
    reason := sprintf("checkov/CKV_AZURE_3: Ensure that 'Secure transfer required' is set to 'Enabled' for azurerm_storage_account %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountsTransportEncryption.py", [resource.address])
}
