package checkov

import rego.v1

valid_azapi_kusto_cluster_double_encryption(resource) if {
    resource.body.properties.enableDoubleEncryption == true
}

deny_CKV_AZURE_75_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Kusto/clusters/2023-08-15"
    not valid_azapi_kusto_cluster_double_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_75: Ensure that Azure Data Explorer uses double encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDataExplorerDoubleEncryptionEnabled.py")
}
