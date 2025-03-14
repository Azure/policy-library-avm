package checkov

import rego.v1

valid_azurerm_postgresql_configuration_log_connections_enabled(resource) if {
    resource.values.name == "log_connections"
    resource.values.value == "on"
}

valid_azapi_postgresql_configuration_log_connections_enabled(resource) if {
    resource.body.properties.value == "on"
}

deny_CKV_AZURE_31 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_configuration")[_]
    not valid_azurerm_postgresql_configuration_log_connections_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_31: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogConnectionsEnabled.py")
}

deny_CKV_AZURE_31_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforPostgreSQL/servers/configurations/2017-12-01"
    not valid_azapi_postgresql_configuration_log_connections_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_31: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogConnectionsEnabled.py")
}
