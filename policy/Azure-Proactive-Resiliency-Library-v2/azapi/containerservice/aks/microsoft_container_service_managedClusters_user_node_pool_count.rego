package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_aks_user_pool_min_node_count(resource) if {
    agentPoolProfiles := resource.values.body.properties.agentPoolProfiles[_]
    mode := "User"
    minCount := 2
    

    valid_pools := name if [name | agentPoolProfiles[i].mode == mode; 
                           agentPoolProfiles[i].minCount >= minCount; 
                           name = agentPoolProfiles[i].name ]
    

    user_pools := name if [name | agentPoolProfiles[i].mode == mode; 
                           name = agentPoolProfiles[i].name ]

    count(valid_pools) == count(user_pools)
}


deny_aks_user_pool_min_node_count contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_aks_user_pool_min_node_count(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/aks_user_pool_min_node_count: '%s' `azapi_resource` must have enabled `agentPoolProfiles.minCount` of two or greater for all `User` pool profiles: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-user-nodepool-count", [resource.address])
}