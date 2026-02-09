package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_web_serverfarms_use_standard_or_premium_tier(resource) if {
  startswith(resource.values.body.sku.name, "P")
}

valid_azapi_web_serverfarms_use_standard_or_premium_tier(resource) if {
  startswith(resource.values.body.sku.name, "S")
}

valid_azapi_web_serverfarms_use_standard_or_premium_tier(resource) if {
  isolated_v2 := { "I1v2", "I2v2", "I3v2", "I4v2", "I5v2", "I6v2" }
  isolated_v2_sku := isolated_v2[_]
  resource.values.body.sku.name == isolated_v2_sku
}

deny_service_plan_use_standard_or_premium_tier contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Web/serverfarms")
    not valid_azapi_web_serverfarms_use_standard_or_premium_tier(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/service_plan_use_standard_or_premium_tier: '%s' `azapi_resource` must be configured to use standard, premium, or isolatedv2 sku tiers: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#use-standard-or-premium-tier", [resource.address])
}