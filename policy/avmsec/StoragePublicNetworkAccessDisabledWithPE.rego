package avmsec

import rego.v1

# For state file: check by resource id
has_private_endpoint_azurerm_storage_account(storage_account) if {
    storage_account_id := storage_account.values.id
    private_endpoint := data.utils.resource(input, "azurerm_private_endpoint")[_]
    private_endpoint.values.private_service_connection[0].private_connection_resource_id == storage_account_id
}

# For plan file: check by configuration references
has_private_endpoint_azurerm_storage_account(storage_account) if {
    private_endpoint_config := data.utils.resource_configuration(input)[_]
    private_endpoint_config.type == "azurerm_private_endpoint"
    data.utils.arraycontains(
        [sprintf("%s%s", [private_endpoint_config.module_prefix, ref]) |
            some ref in private_endpoint_config.expressions.private_service_connection[_].private_connection_resource_id.references],
        sprintf("%s.%s", [storage_account.address, "id"])
    )
}

deny_AVM_SEC_STORAGE_PE_PUBLIC_ACCESS contains reason if {
    storage_account := data.utils.resource(input, "azurerm_storage_account")[_]
    storage_account.values.public_network_access_enabled == true
    has_private_endpoint_azurerm_storage_account(storage_account)
    reason := sprintf("avmsec/AVM_SEC_STORAGE_PE_PUBLIC_ACCESS: Storage account with private endpoint should disable public network access (public_network_access_enabled should be false): %s", [storage_account.address])
}
