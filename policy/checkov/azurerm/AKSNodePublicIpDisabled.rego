package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_node_public_ip_disabled(resource) if {
    resource.values.default_node_pool[0].enable_node_public_ip == false
}

deny_aks_node_public_ip_disabled contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_node_public_ip_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_143: Ensure AKS cluster nodes do not have public IP addresses '%s' `azurerm_kubernetes_cluster`. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNodePublicIpDisabled.py", [resource.address])
}
