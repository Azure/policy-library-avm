package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_redis_cache_enable_zone_redundancy(resource) if {
    count(resource.values.zones) >= 2
}

deny_enable_zone_redundancy_for_azure_cache_for_redis contains reason if {
    resource := data.utils.resource(input, "azurerm_redis_cache")[_]
    not valid_azurerm_redis_cache_enable_zone_redundancy(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/enable_zone_redundancy_for_azure_cache_for_redis: '%s' `azurerm_redis_cache` must have a `zones` attribute that contains at least 2 zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Cache/Redis/#enable-zone-redundancy-for-azure-cache-for-redis", [resource.address])
}