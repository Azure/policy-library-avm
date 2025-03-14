package checkov

import rego.v1

valid_azurerm_databricks_workspace_is_not_public(resource) if {
    resource.values.public_network_access_enabled != true
}

valid_azapi_databricks_workspace_is_not_public(resource) if {
    resource.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_158 contains reason if {
    resource := data.utils.resource(input, "azurerm_databricks_workspace")[_]
    not valid_azurerm_databricks_workspace_is_not_public(resource)

    reason := sprintf("checkov/CKV_AZURE_158: Ensure that databricks workspace has not public %s", [resource.address])

    reason := sprintf("checkov/CKV_AZURE_158: Ensure that databricks workspace has not public %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DatabricksWorkspaceIsNotPublic.py", [resource.address])
}

deny_CKV_AZURE_158 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    not valid_azapi_databricks_workspace_is_not_public(resource)

    reason := sprintf("checkov/CKV_AZURE_158: Ensure that databricks workspace has not public %s", [resource.address])

    reason := sprintf("checkov/CKV_AZURE_158: Ensure that databricks workspace has not public %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DatabricksWorkspaceIsNotPublic.py", [resource.address])
}
