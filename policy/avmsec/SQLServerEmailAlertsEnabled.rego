package avmsec

import rego.v1

valid_azurerm_mssql_server_security_alert_policy_email_addresses(resource) if {
    resource.values.email_addresses == resource.values.email_addresses
}

valid_azurerm_mssql_server_security_alert_policy_email_addresses(resource) if {
    resource.after_unknown.email_addresses == resource.after_unknown.email_addresses
}

deny_AVM_SEC_26 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server_security_alert_policy")[_]
    not valid_azurerm_mssql_server_security_alert_policy_email_addresses(resource)

    reason := sprintf("avmsec/AVM_SEC_26: Ensure that 'Send Alerts To' is enabled for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsEnabled.py", [resource.address])
}
