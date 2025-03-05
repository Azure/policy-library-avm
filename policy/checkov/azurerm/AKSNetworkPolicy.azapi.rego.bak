package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_has_network_policy(resource) if {
    resource.values.network_profile[0].network_policy != null
}

valid_azapi_kubernetes_cluster_has_network_policy(resource) if {
    resource.body.properties.networkProfile.networkPolicy != null
}

deny_CKV_AZURE_7 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_has_network_policy(resource)

    reason := sprintf("checkov/CKV_AZURE_7: Ensure AKS cluster has Network Policy configured %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py", [resource.address])
}

deny_CKV_AZURE_7_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.ContainerService/managedClusters/2024-05-01"
    not valid_azapi_kubernetes_cluster_has_network_policy(resource.changes.after)

    reason := sprintf("checkov/CKV_AZURE_7: Ensure AKS cluster has Network Policy configured %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py", [resource.address])
}
