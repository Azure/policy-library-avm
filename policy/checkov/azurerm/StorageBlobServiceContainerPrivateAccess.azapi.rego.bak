package checkov

import rego.v1

valid_azurerm_storage_container_private_access(resource) if {
    resource.values.container_access_type[0] == "private"
}

valid_azapi_storage_container_private_access(resource) if {
    resource.body.properties.publicAccess == "None"
}

deny_CKV_AZURE_34 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_container")[_]
    not valid_azurerm_storage_container_private_access(resource)

    reason := sprintf("checkov/CKV_AZURE_34: Ensure that 'Public access level' is set to Private for blob containers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobServiceContainerPrivateAccess.py")
}

deny_CKV_AZURE_34_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/blobServices/containers/2023-05-01"
    not valid_azapi_storage_container_private_access(resource)

    reason := sprintf("checkov/CKV_AZURE_34: Ensure that 'Public access level' is set to Private for blob containers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobServiceContainerPrivateAccess.py")
}
