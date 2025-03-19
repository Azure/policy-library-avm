package avmsec

import rego.v1

valid_azurerm_postgresql_server_ssl_enforcement_enabled(resource) if {
    resource.values.ssl_enforcement_enabled == true
}

deny_AVM_SEC_29 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_ssl_enforcement_enabled(resource)

    reason := sprintf("avmsec/AVM_SEC_29: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerSSLEnforcementEnabled.py", [resource.address])
}
