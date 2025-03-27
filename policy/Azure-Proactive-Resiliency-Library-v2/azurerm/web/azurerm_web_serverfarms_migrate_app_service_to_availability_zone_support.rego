package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_web_serverfarms_migrate_app_service_to_availability_zone_support(resource) if {
    resource.values.zone_balancing_enabled == true
}

deny_azurerm_redis_cache_enable_zone_redundancy contains reason if {
    resource := data.utils.resource(input, "azurerm_service_plan")[_]
    not valid_azurerm_web_serverfarms_migrate_app_service_to_availability_zone_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate-app-service-to-availability-zone-support: '%s' `azurerm_service_plan` must have a `zone_balancing_enabled` attribute set to true: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#migrate-app-service-to-availability-zone-support", [resource.address])
}