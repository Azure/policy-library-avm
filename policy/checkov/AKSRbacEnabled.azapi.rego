package checkov

import rego.v1

valid_azapi_kubernetes_cluster_rbac_enabled(resource) if {
    resource.values.body.properties.enableRBAC == true
}

deny_CKV_AZURE_5 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_kubernetes_cluster_rbac_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_5: Ensure RBAC is enabled on AKS clusters %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSRbacEnabled.py", [resource.address])
}
