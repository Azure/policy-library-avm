
package checkov

import rego.v1

valid_azurerm_postgresql_configuration_log_checkpoints(resource) if {
    resource.values.name == "log_checkpoints"
    resource.values.value == "ON"
}

valid_azapi_postgresql_configuration_log_checkpoints(resource) if {
    resource.body.properties.value == "ON"
}

deny_CKV_AZURE_30 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_configuration")[_]
    not valid_azurerm_postgresql_configuration_log_checkpoints(resource)

    reason := sprintf("checkov/CKV_AZURE_30: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogCheckpointsEnabled.py")
}

deny_CKV_AZURE_30 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforPostgreSQL/servers/configurations/2017-12-01"
    not valid_azapi_postgresql_configuration_log_checkpoints(resource)

    reason := sprintf("checkov/CKV_AZURE_30: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogCheckpointsEnabled.py")
}
