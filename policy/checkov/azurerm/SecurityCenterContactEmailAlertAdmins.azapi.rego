package checkov

import rego.v1

valid_azurerm_security_center_contact_alerts_to_admins(resource) if {
    resource.values.alerts_to_admins == true
}

valid_azapi_security_center_contact_alerts_to_admins(resource) if {
    resource.properties.alertsToAdmins == "On"
}

deny_CKV_AZURE_22 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_contact")[_]
    not valid_azurerm_security_center_contact_alerts_to_admins(resource)

    reason := sprintf("checkov/CKV_AZURE_22: Ensure that 'Send email notification for high severity alerts' is set to 'On' for azurerm_security_center_contact '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlertAdmins.py", [resource.address])
}

deny_CKV_AZURE_22_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Security/securityContacts/2017-08-01-preview"
    not valid_azapi_security_center_contact_alerts_to_admins(resource.changes.after)

    reason := sprintf("checkov/CKV_AZURE_22: Ensure that 'Send email notification for high severity alerts' is set to 'On' for azurerm_security_center_contact '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlertAdmins.py", [resource.address])
}
