package avmsec

import rego.v1

valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.private_cluster_enabled == true
}

valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.api_server_authorized_ip_ranges[0] == resource.values.api_server_authorized_ip_ranges[0]
}

valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.api_server_access_profile[0].authorized_ip_ranges[0] == resource.values.api_server_access_profile[0].authorized_ip_ranges[0]
}

deny_AVM_SEC_6 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource)

    reason := sprintf("avmsec/AVM_SEC_6: Ensure AKS has an API Server Authorized IP Ranges enabled %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSApiServerAuthorizedIpRanges.py", [resource.address])
}
