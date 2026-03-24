package avmsec

import rego.v1

# For state file: check by resource id
has_private_endpoint_azapi_storage_account(storage_account) if {
    storage_account_id := storage_account.values.id
    private_endpoint := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(private_endpoint.values, "Microsoft.Network/privateEndpoints")
    private_endpoint.values.body.properties.privateLinkServiceConnections[_].properties.privateLinkServiceId == storage_account_id
}

# For plan file: check by configuration references
has_private_endpoint_azapi_storage_account(storage_account) if {
    private_endpoint_config := data.utils.resource_configuration(input)[_]
    private_endpoint_config.type == "azapi_resource"
    data.utils.arraycontains(
        [sprintf("%s%s", [private_endpoint_config.module_prefix, ref]) |
            some ref in private_endpoint_config.expressions.body.references],
        sprintf("%s.%s", [storage_account.address, "output.id"])
    )
}

deny_AVM_SEC_STORAGE_PE_PUBLIC_ACCESS contains reason if {
    storage_account := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(storage_account.values, "Microsoft.Storage/storageAccounts")
    storage_account.values.body.properties.publicNetworkAccess == "Enabled"
    has_private_endpoint_azapi_storage_account(storage_account)
    reason := sprintf("avmsec/AVM_SEC_STORAGE_PE_PUBLIC_ACCESS: Storage account with private endpoint should disable public network access (publicNetworkAccess should be Disabled): %s", [storage_account.address])
}
