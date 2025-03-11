package checkov

import rego.v1

valid_azapi_security_center_container_registry_subscription_container_registry_pricing_is_standard(resource) if {
    resource.values.name != "ContainerRegistry"
}

valid_azapi_security_center_container_registry_subscription_pricing_is_standard(resource) if {
    resource.values.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_86 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Security/pricings")
    not valid_azapi_security_center_container_registry_subscription_container_registry_pricing_is_standard(resource)

    reason := sprintf("checkov/CKV_AZURE_86: Ensure that Azure Defender is set to On for Container Registries %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnContainerRegistry.py", [resource.address])
}
