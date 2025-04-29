package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_web_serverfarms_migrate_app_service_to_availability_zone_support(resource) if {
    resource.values.zone_balancing_enabled == true
}

valid_azurerm_web_serverfarms_migrate_app_service_to_availability_zone_support(resource) if {
  not startswith(resource.values.sku_name, "I")
  not startswith(resource.values.sku_name, "P")
}

deny_migrate_service_plan_to_availability_zone_support contains reason if {
    resource := data.utils.resource(input, "azurerm_service_plan")[_]
    not valid_azurerm_web_serverfarms_migrate_app_service_to_availability_zone_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate_service_plan_to_availability_zone_support: '%s' `azurerm_service_plan` must have a `zone_balancing_enabled` attribute set to true, or `sku_name` does not start with `I` nor `P`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#migrate-app-service-to-availability-zone-support", [resource.address])
}