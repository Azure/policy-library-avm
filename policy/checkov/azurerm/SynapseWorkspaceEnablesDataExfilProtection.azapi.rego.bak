package checkov

import rego.v1

valid_azurerm_synapse_workspace_data_exfiltration(resource) if {
    resource.values.data_exfiltration_protection_enabled == true
}

valid_azapi_synapse_workspace_data_exfiltration(resource) if {
    resource.body.properties.managedVirtualNetworkSettings.preventDataExfiltration == true
}

deny_CKV_AZURE_157 contains reason if {
    resource := data.utils.resource(input, "azurerm_synapse_workspace")[_]
    not valid_azurerm_synapse_workspace_data_exfiltration(resource)

    reason := sprintf("checkov/CKV_AZURE_157: Ensure that Synapse workspace has data_exfiltration_protection_enabled for %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesDataExfilProtection.py", [resource.address])
}

deny_CKV_AZURE_157 contains reason if {
    resource := data.utils.resource(input, "azapi_resource", "azurerm_synapse_workspace.example")[_]
    not valid_azapi_synapse_workspace_data_exfiltration(resource)

    reason := sprintf("checkov/CKV_AZURE_157: Ensure that Synapse workspace has data_exfiltration_protection_enabled for %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesDataExfilProtection.py", [resource.address])
}
