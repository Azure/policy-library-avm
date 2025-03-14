
package checkov

import rego.v1

valid_azapi_mssql_server_security_alert_policy_no_disabled_alerts(resource) if {
    not resource.values.body.properties.disabledAlerts[0] == resource.values.body.properties.disabledAlerts[0]
    not resource.after_unknown.body.properties.disabledAlerts == resource.after_unknown.body.properties.disabledAlerts
}

deny_CKV_AZURE_25 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Sql/servers/securityAlertPolicies")
    not valid_azapi_mssql_server_security_alert_policy_no_disabled_alerts(resource)

    reason := sprintf("checkov/CKV_AZURE_25: Ensure that 'Threat Detection types' is set to 'All': %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerThreatDetectionTypes.py", [resource.address])
}
