package checkov

import rego.v1

valid_azapi_mssql_server_security_alert_policy_email_addresses(resource) if {
    resource.body.properties.emailAddresses != null
}

deny_CKV_AZURE_26_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Sql/servers/securityAlertPolicies/2020-11-01-preview"
    not valid_azapi_mssql_server_security_alert_policy_email_addresses(resource)

    reason := sprintf("checkov/CKV_AZURE_26: Ensure that 'Send Alerts To' is enabled for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsEnabled.py", [resource.address])
}
