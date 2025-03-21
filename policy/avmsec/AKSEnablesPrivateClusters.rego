package avmsec

import rego.v1

valid_azurerm_kubernetes_cluster_private_cluster_enabled(resource) if {
    resource.values.private_cluster_enabled == true
}

deny_AVM_SEC_115 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_private_cluster_enabled(resource)

    reason := sprintf("avmsec/AVM_SEC_115: Ensure that AKS enables private clusters %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSEnablesPrivateClusters.py", [resource.address])
}
