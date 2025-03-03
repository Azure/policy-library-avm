package checkov

import rego.v1

valid_azurerm_key_vault_purge_protection_enabled(resource) if {
    resource.values.purge_protection_enabled == true
}

valid_azapi_key_vault_purge_protection_enabled(resource) if {
    resource.body.properties.enablePurgeProtection == true
}

deny_CKV_AZURE_110 contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault")[_]
    not valid_azurerm_key_vault_purge_protection_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_110: Ensure that key vault enables purge protection. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesPurgeProtection.py")
}

deny_CKV_AZURE_110 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    not valid_azapi_key_vault_purge_protection_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_110: Ensure that key vault enables purge protection. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesPurgeProtection.py")
}
