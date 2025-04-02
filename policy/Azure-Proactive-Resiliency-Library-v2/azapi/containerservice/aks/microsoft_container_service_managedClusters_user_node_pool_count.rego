package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_aks_user_pool_min_node_count(resource) if {
    valid_pools[resource] {
        pools := resource.values.body.properties.agentPoolProfiles[_] 
        pools.mode == "User"
        pools.minCount >= 2
    }

    user_pools[resource] {
        pools := resource.values.body.properties.agentPoolProfiles[_] 
        pools.mode == "User"
    }

    count(valid_pools) == count(user_pools)
}


deny_aks_user_pool_min_node_count contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_aks_user_pool_min_node_count(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_user_pool_min_node_count: '%s' `azapi_resource` must have enabled `agentPoolProfiles.minCount` of two or greater for all `User` pool profiles: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-user-nodepool-count", [resource.address])
}