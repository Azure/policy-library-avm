
package checkov

import rego.v1

valid_azapi_kubernetes_cluster_dashboard_disabled(resource) if {
    resource.body.properties.addonProfiles == {}
}

valid_azapi_kubernetes_cluster_dashboard_disabled(resource) if {
    addon_profile := resource.body.properties.addonProfiles
    is_object(addon_profile)
    not addon_profile.kube_dashboard.enabled
}

deny_CKV_AZURE_8_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.ContainerService/managedClusters/2024-05-01"
    not valid_azapi_kubernetes_cluster_dashboard_disabled(resource)
    reason := sprintf("checkov/CKV_AZURE_8: Ensure Kubernetes Dashboard is disabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSDashboardDisabled.py")
}
