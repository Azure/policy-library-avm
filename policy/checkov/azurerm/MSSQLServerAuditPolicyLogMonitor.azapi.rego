package checkov

import rego.v1

valid_azurerm_mssql_database_extended_auditing_policy_log_monitoring_enabled(resource) if {
    resource.values.log_monitoring_enabled == true
}

valid_azapi_mssql_database_extended_auditing_policy_log_monitoring_enabled(resource) if {
    resource.body.properties.isAzureMonitorTargetEnabled == true
}

deny_CKV_AZURE_156 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_database_extended_auditing_policy")[_]
    not valid_azurerm_mssql_database_extended_auditing_policy_log_monitoring_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_156: Ensure default Auditing policy for a SQL Server is configured to capture and retain the activity logs %s", [resource.address])

    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerAuditPolicyLogMonitor.py", [reason])
}

deny_CKV_AZURE_156 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Sql/servers/databases/extendedAuditingSettings/2023-08-01-preview"
    not valid_azapi_mssql_database_extended_auditing_policy_log_monitoring_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_156: Ensure default Auditing policy for a SQL Server is configured to capture and retain the activity logs %s", [resource.address])

    reason := sprintf("%s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerAuditPolicyLogMonitor.py", [reason])
}
