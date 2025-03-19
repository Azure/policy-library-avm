package avmsec

import rego.v1

valid_azapi_container_registry_admin_account_disabled(resource) if {
    resource.values.body.properties.adminUserEnabled == false
}

valid_azapi_container_registry_admin_account_disabled(resource) if {
    not resource.values.body.properties.adminUserEnabled == resource.values.body.properties.adminUserEnabled
}

deny_AVM_SEC_137 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerRegistry/registries")
    not valid_azapi_container_registry_admin_account_disabled(resource)

    reason := sprintf("avmsec/AVM_SEC_137: Ensure ACR admin account is disabled %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAdminAccountDisabled.py", [resource.address])
}
