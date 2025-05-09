package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_configure_aks_default_node_pool_autoscale_enabled(resource) if {
    every pool in resource.values.default_node_pool {
        pool.auto_scaling_enabled == true
    }
}

deny_aks_enable_cluster_autoscaler contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_configure_aks_default_node_pool_autoscale_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_enable_cluster_autoscaler: '%s' `azurerm_kubernetes_cluster` must have configured `default_node_pool` to have autoscale enabled: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#enable-the-cluster-auto-scaler-on-an-existing-cluster", [resource.address])
}