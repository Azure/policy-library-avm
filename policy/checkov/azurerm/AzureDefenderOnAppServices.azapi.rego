package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_is_standard(resource) if {
    resource.values.resource_type != "AppServices"
}

valid_azurerm_security_center_subscription_pricing_is_standard(resource) if {
    resource.values.tier == "Standard"
}

deny_CKV_AZURE_61 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_is_standard(resource)

    reason := sprintf("checkov/CKV_AZURE_61: Ensure that Azure Defender is set to On for App Service. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnAppServices.py")
}


valid_azapi_security_center_subscription_pricing_is_standard(resource) if {
    resource.changes.after.type != "Microsoft.Security/pricings/2023-01-01"
}

valid_azapi_security_center_subscription_pricing_is_standard(resource) if {
    resource.changes.after.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_61_azapi contains reason if {
    resource := input.mock.default.resource_changes[_]
    resource.type == "azapi_resource"
    resource.address == "azurerm_security_center_subscription_pricing.example"
    not valid_azapi_security_center_subscription_pricing_is_standard(resource)

    reason := sprintf("checkov/CKV_AZURE_61: Ensure that Azure Defender is set to On for App Service. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnAppServices.py")
}
