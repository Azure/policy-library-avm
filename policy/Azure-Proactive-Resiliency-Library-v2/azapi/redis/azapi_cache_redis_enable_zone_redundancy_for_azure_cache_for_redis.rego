package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_enable_zone_redundancy_for_azure_cache_for_redis(resource) if {
    resource.values.body.zones == resource.values.body.zones
    count(resource.values.body.zones) >= 2
}


deny_enable_zone_redundancy_for_azure_cache_for_redis contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Cache/redis")
    not valid_azapi_enable_zone_redundancy_for_azure_cache_for_redis(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/enable_zone_redundancy_for_azure_cache_for_redis: '%s' `azapi_resource` must be configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Cache/Redis/#enable-zone-redundancy-for-azure-cache-for-redis", [resource.address])
}