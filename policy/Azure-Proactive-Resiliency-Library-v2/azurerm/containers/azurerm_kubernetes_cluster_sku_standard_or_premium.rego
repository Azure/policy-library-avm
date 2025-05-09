package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_aks_sku_standard_or_premium(resource) if {
    valid_sku_types := {"Premium", "Standard"}
    some sku in valid_sku_types
    resource.values.sku_tier == sku
}

deny_aks_sku_standard_or_premium contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_aks_sku_standard_or_premium(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_sku_standard_or_premium: '%s' `azurerm_kubernetes_cluster` must have `sku_tier` set to `Standard`` or `Premium`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#update-aks-tier-to-standard-or-premium", [resource.address])
}