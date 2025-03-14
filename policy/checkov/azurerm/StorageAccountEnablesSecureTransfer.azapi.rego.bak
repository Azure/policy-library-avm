
package checkov

import rego.v1

valid_azapi_storage_account_enables_secure_transfer(resource) if {
    resource.body.properties.supportsHttpsTrafficOnly == true
}

deny_CKV_AZURE_60_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/2023-05-01"
    not valid_azapi_storage_account_enables_secure_transfer(resource)

    reason := sprintf("checkov/CKV_AZURE_60: Ensure that storage account enables secure transfer %s", [resource.address])
}
