package checkov

import rego.v1

valid_azapi_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.body.properties.apiServerAccessProfile.enablePrivateCluster == true
}

valid_azapi_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.body.properties.apiServerAccessProfile.authorizedIPRanges[_]
}

deny_CKV_AZURE_6 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_kubernetes_cluster_api_server_authorized_ip_ranges(resource)

    reason := sprintf("checkov/CKV_AZURE_6: Ensure AKS has an API Server Authorized IP Ranges enabled %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSApiServerAuthorizedIpRanges.py", [resource.address])
}
