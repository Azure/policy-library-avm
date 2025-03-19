package avmsec

import rego.v1

valid_azapi_service_fabric_cluster_has_active_directory(resource) if {
    resource.values.body.properties.azureActiveDirectory.tenantId == resource.values.body.properties.azureActiveDirectory.tenantId
}

valid_azapi_service_fabric_cluster_has_active_directory(resource) if {
    resource.after_unknown.body.properties.azureActiveDirectory.tenantId == resource.after_unknown.body.properties.azureActiveDirectory.tenantId
}

deny_AVM_SEC_126 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ServiceFabric/clusters")
    not valid_azapi_service_fabric_cluster_has_active_directory(resource)

    reason := sprintf("avmsec/AVM_SEC_126: Ensure that Active Directory is used for authentication for Service Fabric %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ActiveDirectoryUsedAuthenticationServiceFabric.py", [resource.address])
}
