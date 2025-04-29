package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_aks_system_pool_min_node_count(resource) if {
    pool := resource.values.default_node_pool[_]
    pool.min_count >= 2
}

deny_aks_system_pool_min_node_count contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_aks_system_pool_min_node_count(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_system_pool_min_node_count: '%s' `azurerm_kubernetes_cluster` must have configured `default_node_pool` to use at least 2 nodes: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-system-nodepool-count", [resource.address])
}
