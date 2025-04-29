package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_aks_sku_standard_or_premium(resource) if {
    valid_sku_types := {"Premium", "Standard"}
    some sku in valid_sku_types
    resource.values.body.sku.tier == sku
}

deny_aks_sku_standard_or_premium contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_aks_sku_standard_or_premium(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_sku_standard_or_premium: '%s' `azapi_resource` must have `sku.tier` of `Standard` or `Premium`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#update-aks-tier-to-standard-or-premium", [resource.address])
}