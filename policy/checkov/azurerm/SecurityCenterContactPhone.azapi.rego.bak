
package checkov

import rego.v1

valid_azapi_security_center_contact_phone_is_set(resource) if {
    resource.values.body.properties.phone != null
}

deny_CKV_AZURE_20_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "azurerm_security_center_contact.example"
    not valid_azapi_security_center_contact_phone_is_set(resource)

    reason := sprintf("checkov/CKV_AZURE_20: Ensure that security contact 'Phone number' is set https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactPhone.py", [])
}
