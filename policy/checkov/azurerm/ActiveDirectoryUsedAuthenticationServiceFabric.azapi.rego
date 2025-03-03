package checkov

import rego.v1

valid_azapi_service_fabric_cluster_has_active_directory(resource) if {
    resource.body.properties.azureActiveDirectory.tenantId != null
}

deny_CKV_AZURE_126_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.ServiceFabric/clusters/2021-06-01"
    not valid_azapi_service_fabric_cluster_has_active_directory(resource)

    reason := sprintf("checkov/CKV_AZURE_126: Ensure that Active Directory is used for authentication for Service Fabric %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ActiveDirectoryUsedAuthenticationServiceFabric.py", [resource.address])
}
