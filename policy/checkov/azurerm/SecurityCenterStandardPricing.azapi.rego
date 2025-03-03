package checkov

import rego.v1

valid_azapi_security_center_subscription_pricing_tier_is_standard(resource) if {
    resource.values.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_19_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.values.type == "Microsoft.Security/pricings/2023-01-01"
    not valid_azapi_security_center_subscription_pricing_tier_is_standard(resource)

    reason := sprintf("checkov/CKV_AZURE_19: Ensure that standard pricing tier is selected for azurerm_security_center_subscription_pricing. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterStandardPricing.py")
}
