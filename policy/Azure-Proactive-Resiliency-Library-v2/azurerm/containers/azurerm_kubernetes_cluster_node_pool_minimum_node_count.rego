package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_aks_user_pool_min_node_count(resource) if {
    resource.values.min_count >= 2
}

deny_aks_user_pool_min_node_count contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster_node_pool")[_]
    not valid_azurerm_aks_user_pool_min_node_count(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aaks_user_pool_min_node_count: '%s' `azurerm_kubernetes_cluster_node_pool` must be configured to use at least 2 nodes: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-user-nodepool-count", [resource.address])
}