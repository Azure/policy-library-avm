package checkov

import rego.v1

valid_azapi_kubernetes_cluster_local_admin_disabled(resource) if {
    resource.values.body.properties.disableLocalAccounts == true
}

deny_CKV_AZURE_141 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_kubernetes_cluster_local_admin_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_141: Ensure AKS local admin account is disabled %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLocalAdminDisabled.py", [resource.address])
}
