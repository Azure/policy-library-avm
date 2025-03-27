package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource) if {
    some word in {"P", "I", "S"}
    count(contains(resource.values.body.properties.sku.name, word)) == 1
}

deny_azurerm_web_serverfarms_use_standard_or_premium_tier contains reason if {
    resource := data.utils.resource(input, "azurerm_service_plan")[_]
    not valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/use-standard-or-premium-tier: '%s' `azurerm_service_plan` should use standard, premium, or isolated sku tiers: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#use-standard-or-premium-tier", [resource.address])
}