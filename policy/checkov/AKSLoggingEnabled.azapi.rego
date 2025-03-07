package checkov

import rego.v1

valid_azapi_kubernetes_cluster_logging_enabled(resource) if {
    resource.values.body.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID == resource.values.body.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID
}

valid_azapi_kubernetes_cluster_logging_enabled(resource) if {
    resource.after_unknown.body.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID == resource.after_unknown.body.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID
}

deny_CKV_AZURE_4 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_azapi_kubernetes_cluster_logging_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py", [resource.address])
}
