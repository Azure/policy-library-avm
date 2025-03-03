package checkov

import rego.v1

valid_azurerm_container_registry_public_network_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

valid_azapi_container_registry_public_network_access_disabled(resource) if {
    resource.changes.after.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_139 contains reason if {
    resource := data.utils.resource(input, "azurerm_container_registry")[_]
    not valid_azurerm_container_registry_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_139: Ensure ACR set to disable public networking %s", [resource.address])
    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py", [reason])
}

deny_CKV_AZURE_139 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.changes.after.type == "Microsoft.ContainerRegistry/registries"
    not valid_azapi_container_registry_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_139: Ensure ACR set to disable public networking %s", [resource.address])
    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py", [reason])
}
