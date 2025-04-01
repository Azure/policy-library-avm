package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_aks_enable_cluster_autoscaler(resource) if {
    every pool in resource.values.body.properties.agentPoolProfiles {
        pool.enableAutoScaling == true
    }
}

deny_aks_enable_cluster_autoscaler contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_aks_enable_cluster_autoscaler(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_enable_cluster_autoscaler: '%s' `azapi_resource` must have enabled `agentPoolProfiles.enableClusterAutoscaler` for all pool profiles: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#enable-the-cluster-auto-scaler-on-an-existing-cluster", [resource.address])
}