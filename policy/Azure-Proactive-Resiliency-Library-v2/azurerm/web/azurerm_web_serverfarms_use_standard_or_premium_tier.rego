package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource) if {
  startswith(resource.values.sku_name, "P")
}

valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource) if {
  startswith(resource.values.sku_name, "S")
}

valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource) if {
  isolated_v2 := { "I1v2", "I2v2", "I3v2", "I4v2", "I5v2", "I6v2" }
  isolated_v2_sku := isolated_v2[_]
  resource.values.sku_name == isolated_v2_sku
}

deny_service_plan_use_standard_or_premium_tier contains reason if {
    resource := data.utils.resource(input, "azurerm_service_plan")[_]
    not valid_azurerm_web_serverfarms_use_standard_or_premium_tier(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/service_plan_use_standard_or_premium_tier: '%s' `azurerm_service_plan` should use standard, premium, or isolated sku tiers: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#use-standard-or-premium-tier", [resource.address])
}