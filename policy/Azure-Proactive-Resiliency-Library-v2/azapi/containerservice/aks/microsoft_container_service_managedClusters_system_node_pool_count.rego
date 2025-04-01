package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_aks_system_pool_min_node_count(resource) if {
    some pool in resource.values.body.properties.agentPoolProfiles {
        pool.mode == "System"  
        pool.minCount >= 2
    }
}

deny_aks_system_pool_min_node_count contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_aks_system_pool_min_node_count(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_system_pool_min_node_count: '%s' `azapi_resource` must have enabled `agentPoolProfiles.minCount` of two or greater for the `System` mode pool profile: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-system-nodepool-count", [resource.address])
}