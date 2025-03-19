package checkov

import rego.v1

# For seperated `azurerm_storage_account_customer_managed_key` resource
valid_azurerm_storage_critical_data_encrypted_cmk(resource) if {
    address_segments := split(resource.address, ".")
    local_resource_name := regex.replace(concat(".", array.slice(address_segments, count(address_segments) - 2 ,count(address_segments))), "\\[.*\\]", "")
    storage_account_cmk_resource := data.utils.resource(input, "azurerm_storage_account_customer_managed_key")[_]
    storage_account_cmk_resource_address_without_index := regex.replace(storage_account_cmk_resource.address, "\\[.*\\]", "")
    reference := data.utils.resource_configuration(input)[storage_account_cmk_resource_address_without_index].expressions.storage_account_id.references[_]
    reference == local_resource_name
}

# For nested `customer_managed_key` block
valid_azurerm_storage_critical_data_encrypted_cmk(resource) if {
    resource.values.customer_managed_key[_].key_vault_key_id == resource.values.customer_managed_key[_].key_vault_key_id
}

valid_azurerm_storage_critical_data_encrypted_cmk(resource) if {
    resource.after_unknown.customer_managed_key[_].key_vault_key_id == resource.after_unknown.customer_managed_key[_].key_vault_key_id
}

# For json exported from existing state file
valid_azurerm_storage_critical_data_encrypted_cmk(resource) if {
    storage_account_id := resource.values.id
    storage_account_cmk_resource := data.utils.resource(input, "azurerm_storage_account_customer_managed_key")[_]
    storage_account_cmk_resource.values.storage_account_id == storage_account_id
}

deny_CKV2_AZURE_1 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_critical_data_encrypted_cmk(resource)
    reason := sprintf("checkov/CKV2_AZURE_1: Enable sensitive data encryption at rest using Customer Managed Keys (CMKs) rather than Microsoft Managed keys. : %s https://docs.prismacloud.io/en/enterprise-edition/policy-reference/azure-policies/azure-general-policies/ensure-storage-for-critical-data-are-encrypted-with-customer-managed-key", [resource.address])
}
