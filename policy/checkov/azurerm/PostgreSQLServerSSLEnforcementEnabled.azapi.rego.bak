package checkov

import rego.v1

valid_azurerm_postgresql_server_ssl_enforcement_enabled(resource) if {
    resource.values.ssl_enforcement_enabled == true
}

valid_azapi_postgresql_server_ssl_enforcement_enabled(resource) if {
    resource.body.properties.sslEnforcement == "Enabled"
}

deny_CKV_AZURE_29 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_ssl_enforcement_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_29: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerSSLEnforcementEnabled.py", [])
}

deny_CKV_AZURE_29 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforPostgreSQL/servers/2017-12-01"
    not valid_azapi_postgresql_server_ssl_enforcement_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_29: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerSSLEnforcementEnabled.py", [])
}
