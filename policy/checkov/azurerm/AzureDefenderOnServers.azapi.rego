
package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing(resource) if {
    resource.values.resource_type != "VirtualMachines"
}

valid_azurerm_security_center_subscription_pricing(resource) if {
    resource.values.tier == "Standard"
}

deny_CKV_AZURE_55 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing(resource)

    reason := sprintf("checkov/CKV_AZURE_55: Ensure that Azure Defender is set to On for Servers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnServers.py")
}

valid_azapi_security_center_subscription_pricing(resource) if {
    resource.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_55_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Security/pricings/2023-01-01"
    not valid_azapi_security_center_subscription_pricing(resource)

    reason := sprintf("checkov/CKV_AZURE_55: Ensure that Azure Defender is set to On for Servers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnServers.py")
}
