package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_is_on(resource) if {
    resource.values.resource_type != "StorageAccounts"
}

valid_azurerm_security_center_subscription_pricing_is_on(resource) if {
    resource.values.tier == "Standard"
}

valid_azapi_security_center_subscription_pricing_is_on(resource) if {
    resource.changes.after.body.properties.pricingTier == "Standard"
}


deny_CKV_AZURE_84 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_is_on(resource)

    reason := sprintf("checkov/CKV_AZURE_84: Ensure that Azure Defender is set to On for Storage. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnStorage.py")
}

deny_CKV_AZURE_84 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.address == "azurerm_security_center_subscription_pricing.example_storage"
    not valid_azapi_security_center_subscription_pricing_is_on(resource)

    reason := sprintf("checkov/CKV_AZURE_84: Ensure that Azure Defender is set to On for Storage. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnStorage.py")
}
