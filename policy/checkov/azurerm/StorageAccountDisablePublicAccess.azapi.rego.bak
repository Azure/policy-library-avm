package checkov

import rego.v1

valid_azapi_storage_account_no_public_access(resource) if {
    resource.body.properties.allowBlobPublicAccess == false
}

deny_CKV_AZURE_59_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/2023-05-01"
    not valid_azapi_storage_account_no_public_access(resource)

    reason := sprintf("checkov/CKV_AZURE_59: Ensure that Storage accounts disallow public access. Resource %s allows public access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDisablePublicAccess.py", [resource.address])
}
