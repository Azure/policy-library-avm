
package checkov

import rego.v1

valid_azapi_storage_account_name(resource) if {
    name := resource.address
    re_match("^[a-z0-9]{3,24}$", name)
}

deny_CKV_AZURE_43_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.resource_changes[_].address
    not valid_azapi_storage_account_name(resource)

    reason := sprintf("checkov/CKV_AZURE_43: Storage Account %s does not adhere to the naming rules: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountName.py", [resource.resource_changes[_].address])
}
