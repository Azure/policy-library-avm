package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_postgres_flexible_server_custom_maintenance_window_enabled(resource) if {
    resource.values.body.properties.maintenanceWindow.customWindow == "Enabled"
}

deny_postgresql_flexible_server_custom_maintenance_window_enabled contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DBforPostgreSQL/flexibleServers")
    not valid_azapi_postgres_flexible_server_custom_maintenance_window_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/postgresql_flexible_server_custom_maintenance_window_enabled: '%s' `azapi_resource` must have 'maintenanceWindow.customWindow' set to '\"Enabled\"': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-custom-maintenance-schedule", [resource.address])
}