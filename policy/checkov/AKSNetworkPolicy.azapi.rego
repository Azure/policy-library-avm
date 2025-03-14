package checkov

import rego.v1


valid_azapi_kubernetes_cluster_has_network_policy(resource) if {
    resource.values.body.properties.networkProfile.networkPolicy == resource.values.body.properties.networkProfile.networkPolicy
}

valid_azapi_kubernetes_cluster_has_network_policy(resource) if {
    resource.after_unknown.body.properties.networkProfile.networkPolicy == resource.after_unknown.body.properties.networkProfile.networkPolicy
}

deny_CKV_AZURE_7 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_kubernetes_cluster_has_network_policy(resource)

    reason := sprintf("checkov/CKV_AZURE_7: Ensure AKS cluster has Network Policy configured %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py", [resource.address])
}
