package avmsec

import rego.v1

valid_azurerm_kubernetes_cluster_has_network_policy(resource) if {
    resource.values.network_profile[0].network_policy == resource.values.network_profile[0].network_policy
}

valid_azurerm_kubernetes_cluster_has_network_policy(resource) if {
    resource.after_unknown.network_profile[0].network_policy == resource.after_unknown.network_profile[0].network_policy
}

deny_AVM_SEC_7 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_has_network_policy(resource)

    reason := sprintf("avmsec/AVM_SEC_7: Ensure AKS cluster has Network Policy configured %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py", [resource.address])
}
