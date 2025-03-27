package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_web_serverfarms_migrate_app_service_to_availability_zone_support(resource) if {
    resource.values.body.properties.zoneRedundant == true
}


deny_azapi_enable_zone_redundancy_for_azure_cache_for_redis contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Web/serverfarms")
    not valid_azapi_web_serverfarms_migrate_app_service_to_availability_zone_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate-app-service-to-availability-zone-support: '%s' `azapi_resource` must be configured for zone redundancy: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#migrate-app-service-to-availability-zone-support", [resource.address])
}