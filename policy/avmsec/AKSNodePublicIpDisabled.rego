package avmsec

import rego.v1

invalid_azurerm_kubernetes_cluster_node_public_ip_disabled(resource) if {
    resource.values.default_node_pool[0].enable_node_public_ip == true
}

invalid_azurerm_kubernetes_cluster_node_public_ip_disabled(resource) if {
    resource.values.default_node_pool[0].node_public_ip_enabled == true
}

deny_AVM_SEC_143 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    invalid_azurerm_kubernetes_cluster_node_public_ip_disabled(resource)

    reason := sprintf("avmsec/AVM_SEC_143: Ensure AKS cluster nodes do not have public IP addresses %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNodePublicIpDisabled.py", [resource.address])
}
