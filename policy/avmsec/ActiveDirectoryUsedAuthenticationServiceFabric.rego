package avmsec

import rego.v1

valid_azurerm_service_fabric_cluster_has_active_directory(resource) if {
    resource.values.azure_active_directory[0].tenant_id == resource.values.azure_active_directory[0].tenant_id
}

valid_azurerm_service_fabric_cluster_has_active_directory(resource) if {
    resource.after_unknown.azure_active_directory[0].tenant_id == resource.after_unknown.azure_active_directory[0].tenant_id
}

deny_AVM_SEC_126 contains reason if {
    resource := data.utils.resource(input, "azurerm_service_fabric_cluster")[_]
    not valid_azurerm_service_fabric_cluster_has_active_directory(resource)

    reason := sprintf("avmsec/AVM_SEC_126: Ensure that Active Directory is used for authentication for Service Fabric %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ActiveDirectoryUsedAuthenticationServiceFabric.py", [resource.address])
}
