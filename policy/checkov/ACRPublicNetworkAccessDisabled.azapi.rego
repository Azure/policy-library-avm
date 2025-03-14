package checkov

import rego.v1

valid_azapi_container_registry_public_network_access_disabled(resource) if {
    resource.values.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_139 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerRegistry/registries")
    not valid_azapi_container_registry_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_139: Ensure ACR set to disable public networking: %s, https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py", [resource.address])
}
