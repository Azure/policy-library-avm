package avmsec

import rego.v1

valid_azurerm_mssql_server_security_alert_policy_no_disabled_alerts(resource) if {
    not resource.values.disabled_alerts[0] == resource.values.disabled_alerts[0]
    not resource.after_unknown.disabled_alerts == resource.after_unknown.disabled_alerts
}

deny_AVM_SEC_25 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server_security_alert_policy")[_]
    not valid_azurerm_mssql_server_security_alert_policy_no_disabled_alerts(resource)

    reason := sprintf("avmsec/AVM_SEC_25: Ensure that 'Threat Detection types' is set to 'All': %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerThreatDetectionTypes.py", [resource.address])
}
