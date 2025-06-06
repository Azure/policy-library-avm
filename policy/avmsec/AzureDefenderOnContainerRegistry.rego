package avmsec

import rego.v1

valid_azurerm_security_center_container_registry_subscription_pricing_is_standard(resource) if {
    resource.values.resource_type != "ContainerRegistry"
}

valid_azurerm_security_center_container_registry_subscription_pricing_is_standard(resource) if {
    resource.values.tier == "Standard"
}

deny_AVM_SEC_86 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_container_registry_subscription_pricing_is_standard(resource)

    reason := sprintf("avmsec/AVM_SEC_86: Ensure that Azure Defender is set to On for Container Registries %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnContainerRegistry.py", [resource.address])
}
