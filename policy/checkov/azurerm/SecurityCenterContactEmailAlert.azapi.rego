package checkov

import rego.v1

valid_azapi_security_center_contact_alert_notifications(resource) if {
    resource.body.properties.alertNotifications == "On"
}

deny_CKV_AZURE_21_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Security/securityContacts/2017-08-01-preview"
    not valid_azapi_security_center_contact_alert_notifications(resource)

    reason := sprintf("checkov/CKV_AZURE_21: Ensure that 'Send email notification for high severity alerts' is set to 'On' for azapi_resource %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlert.py", [resource.address])
}
