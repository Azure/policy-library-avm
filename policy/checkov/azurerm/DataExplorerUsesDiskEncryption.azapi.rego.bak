package checkov

import rego.v1

valid_azapi_kusto_cluster_disk_encryption(resource) if {
    resource.body.properties.enableDiskEncryption == true
}

deny_CKV_AZURE_74_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Kusto/clusters"
    not valid_azapi_kusto_cluster_disk_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_74: Ensure that Azure Data Explorer uses disk encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataExplorerUsesDiskEncryption.py")
}
