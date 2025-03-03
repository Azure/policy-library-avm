package checkov

import rego.v1

valid_azurerm_batch_account_uses_key_vault_encryption(resource) if {
    resource.values.key_vault_reference[_].id != null
}

valid_azapi_batch_account_uses_key_vault_encryption(resource) if {
    resource.body.properties.encryption.keySource == "Microsoft.KeyVault"
}

deny_CKV_AZURE_76 contains reason if {
    resource := data.utils.resource(input, "azurerm_batch_account")[_]
    not valid_azurerm_batch_account_uses_key_vault_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_76: Ensure that Azure Batch account uses key vault to encrypt data. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureBatchAccountUsesKeyVaultEncryption.py")
}

deny_CKV_AZURE_76 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Batch/batchAccounts/2024-07-01"
    not valid_azapi_batch_account_uses_key_vault_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_76: Ensure that Azure Batch account uses key vault to encrypt data. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureBatchAccountUsesKeyVaultEncryption.py")
}
