package avmsec

import rego.v1

valid_azurerm_kusto_cluster_double_encryption(resource) if {
    resource.values.double_encryption_enabled == true
}

deny_AVM_SEC_75 contains reason if {
    resource := data.utils.resource(input, "azurerm_kusto_cluster")[_]
    not valid_azurerm_kusto_cluster_double_encryption(resource)

    reason := sprintf("avmsec/AVM_SEC_75: Ensure that Azure Data Explorer uses double encryption %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDataExplorerDoubleEncryptionEnabled.py", [resource.address])
}
