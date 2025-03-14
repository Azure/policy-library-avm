package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_logging_enabled(_input) if {
    _input.values.addon_profile[0].oms_agent[0].enabled == true
}

valid_azurerm_kubernetes_cluster_logging_enabled(_input) if {
    _input.values.oms_agent[0].log_analytics_workspace_id == _input.values.oms_agent[0].log_analytics_workspace_id
}

valid_azurerm_kubernetes_cluster_logging_enabled(_input) if {
    _input.after_unknown.oms_agent[0].log_analytics_workspace_id == _input.after_unknown.oms_agent[0].log_analytics_workspace_id
}

deny_CKV_AZURE_4 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_logging_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured. %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py", [resource.address])
}
