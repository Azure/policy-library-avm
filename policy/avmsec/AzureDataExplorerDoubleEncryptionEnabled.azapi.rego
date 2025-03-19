package avmsec

import rego.v1

valid_azapi_kusto_cluster_double_encryption(resource) if {
    resource.values.body.properties.enableDoubleEncryption == true
}

deny_AVM_SEC_75 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Kusto/clusters")
    not valid_azapi_kusto_cluster_double_encryption(resource)

    reason := sprintf("avmsec/AVM_SEC_75: Ensure that Azure Data Explorer uses double encryption %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDataExplorerDoubleEncryptionEnabled.py", [resource.address])
}
