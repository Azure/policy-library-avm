package checkov

import rego.v1

valid_azurerm_redis_cache_min_tls_version(resource) if {
    resource.values.minimum_tls_version == "1.2"
}

valid_azapi_redis_cache_min_tls_version(resource) if {
    resource.body.properties.minimumTlsVersion == "1.2"
}

deny_CKV_AZURE_148 contains reason if {
    resource := data.utils.resource(input, "azurerm_redis_cache")[_]
    not valid_azurerm_redis_cache_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_148: Ensure Redis Cache is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheMinTLSVersion.py")
}

deny_CKV_AZURE_148 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Cache/redis/2024-03-01"
    not valid_azapi_redis_cache_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_148: Ensure Redis Cache is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheMinTLSVersion.py")
}
