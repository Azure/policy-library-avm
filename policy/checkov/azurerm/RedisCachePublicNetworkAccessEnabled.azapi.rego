package checkov

import rego.v1

valid_azurerm_redis_cache_public_network_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

valid_azapi_redis_cache_public_network_access_disabled(resource) if {
    resource.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_89 contains reason if {
    resource := data.utils.resource(input, "azurerm_redis_cache")[_]
    not valid_azurerm_redis_cache_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_89: Ensure that Azure Cache for Redis disables public network access. Resource %s has public_network_access_enabled set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCachePublicNetworkAccessEnabled.py", [resource.address])
}

deny_CKV_AZURE_89 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Cache/redis/2024-03-01"
    not valid_azapi_redis_cache_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_89: Ensure that Azure Cache for Redis disables public network access. Resource %s has public_network_access_enabled set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCachePublicNetworkAccessEnabled.py", [resource.address])
}
