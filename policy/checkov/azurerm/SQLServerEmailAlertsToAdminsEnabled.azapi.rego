package checkov

import rego.v1

valid_azurerm_mssql_server_security_alert_policy_email_account_admins_enabled(resource) if {
    resource.values.email_account_admins == "Enabled"
}

valid_azapi_mssql_server_security_alert_policy_email_account_admins_enabled(resource) if {
    resource.body.properties.emailAccountAdmins == true
}

deny_CKV_AZURE_27 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server_security_alert_policy")[_]
    not valid_azurerm_mssql_server_security_alert_policy_email_account_admins_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_27: Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsToAdminsEnabled.py", [resource.address])
}

deny_CKV_AZURE_27_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Sql/servers/securityAlertPolicies/2020-11-01-preview"
    not valid_azapi_mssql_server_security_alert_policy_email_account_admins_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_27: Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsToAdminsEnabled.py", [resource.address])
}
