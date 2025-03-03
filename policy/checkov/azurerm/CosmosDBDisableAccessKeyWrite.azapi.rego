package checkov

import rego.v1

valid_azapi_cosmosdb_access_key_metadata_writes_enabled(resource) if {
    resource.body.properties.disableKeyBasedMetadataWriteAccess == true
}

deny_CKV_AZURE_132_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DocumentDB/databaseAccounts/2024-08-15"
    not valid_azapi_cosmosdb_access_key_metadata_writes_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_132: Ensure cosmosdb does not allow privileged escalation by restricting management plane changes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisableAccessKeyWrite.py")
}
