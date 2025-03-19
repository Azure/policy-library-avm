package avmsec

import rego.v1

valid_azapi_mssql_server_security_alert_policy_email_addresses(resource) if {
    address := resource.values.body.properties.emailAddresses[_]
    address == address
}

valid_azapi_mssql_server_security_alert_policy_email_addresses(resource) if {
    resource.after_unknown.body.properties.emailAddresses
}

deny_AVM_SEC_26 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Sql/servers/securityAlertPolicies")

    not valid_azapi_mssql_server_security_alert_policy_email_addresses(resource)

    reason := sprintf("avmsec/AVM_SEC_26: Ensure that 'Send Alerts To' is enabled for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsEnabled.py", [resource.address])
}
