package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_postgresql_flexible_server_custom_maintenance_window_enabled(resource) if {
    resource.values.maintenance_window[_].day_of_week >= 0
}

deny_postgresql_flexible_server_custom_maintenance_window_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_flexible_server")[_]
    not valid_azurerm_postgresql_flexible_server_custom_maintenance_window_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/postgresql_flexible_server_custom_maintenance_window_enabled: '%s' `azurerm_postgresql_flexible_server` must have a 'maintenance_window' block defined: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-custom-maintenance-schedule", [resource.address])
}