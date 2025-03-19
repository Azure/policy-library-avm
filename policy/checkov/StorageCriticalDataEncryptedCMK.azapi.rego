package checkov

import rego.v1

valid_azapi_storage_critical_data_encrypted_cmk(resource) if {
    resource.values.body.properties.encryption.keyvaultproperties.keyname == resource.values.body.properties.encryption.keyvaultproperties.keyname
}

valid_azapi_storage_critical_data_encrypted_cmk(resource) if {
    resource.after_unknown.body.properties.encryption.keyvaultproperties.keyname == resource.after_unknown.body.properties.encryption.keyvaultproperties.keyname
}

deny_CKV2_AZURE_1 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Storage/storageAccounts")
    not valid_azapi_storage_critical_data_encrypted_cmk(resource)
    reason := sprintf("checkov/CKV2_AZURE_1: Enable sensitive data encryption at rest using Customer Managed Keys (CMKs) rather than Microsoft Managed keys. : %s https://docs.prismacloud.io/en/enterprise-edition/policy-reference/azure-policies/azure-general-policies/ensure-storage-for-critical-data-are-encrypted-with-customer-managed-key", [resource.address])
}
