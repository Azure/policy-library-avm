package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_logging_enabled(resource) if {
    (resource.addon_profile.oms_agent.enabled == true) or (resource.oms_agent.log_analytics_workspace_id != null)
}

valid_azapi_kubernetes_cluster_logging_enabled(resource) if {
    (resource.properties.addonProfiles.oms_agent.enabled == true) or (resource.properties.oms_agent.log_analytics_workspace_id != null)
}

deny_CKV_AZURE_4 contains reason if {
    resource := input.resource.azurerm_kubernetes_cluster[_]
    not valid_azurerm_kubernetes_cluster_logging_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py")
}

deny_CKV_AZURE_4_azapi contains reason if {
    resource_changes := input.mock.default.resource_changes[_]
    resource_changes.type == "azapi_resource"
    resource := resource_changes.changes.after
    not valid_azapi_kubernetes_cluster_logging_enabled(resource.body)

    reason := sprintf("checkov/CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py")
}
