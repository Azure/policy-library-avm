package checkov

import rego.v1

valid_azurerm_storage_account_min_tls_version(resource) if {
    resource.values.min_tls_version != null
    contains(["TLS1_2", "TLS1_3"], resource.values.min_tls_version)
}

valid_azapi_storage_account_min_tls_version(resource) if {
    resource.body.properties.minimumTlsVersion != null
    contains(["TLS1_2", "TLS1_3"], resource.body.properties.minimumTlsVersion)
}

deny_CKV_AZURE_44 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_44: Ensure Storage Account is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountMinimumTlsVersion.py")
}

deny_CKV_AZURE_44_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/2023-05-01"
    not valid_azapi_storage_account_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_44: Ensure Storage Account is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountMinimumTlsVersion.py")
}
