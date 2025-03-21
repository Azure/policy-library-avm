package avmsec

import rego.v1

valid_azurerm_kubernetes_cluster_rbac_enabled(resource) if {
    resource.values.role_based_access_control[0].enabled == true
}

valid_azurerm_kubernetes_cluster_rbac_enabled(resource) if {
    resource.values.role_based_access_control_enabled == true
}

deny_AVM_SEC_5 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_rbac_enabled(resource)

    reason := sprintf("avmsec/AVM_SEC_5: Ensure RBAC is enabled on AKS clusters %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSRbacEnabled.py", [resource.address])
}
