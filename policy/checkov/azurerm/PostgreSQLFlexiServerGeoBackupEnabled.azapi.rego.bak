
package checkov

import rego.v1

valid_azapi_postgresql_flexible_server_geo_backup_enabled(resource) if {
    resource.body.properties.backup.geoRedundantBackup == "Enabled"
}

deny_CKV_AZURE_136_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforPostgreSQL/flexibleServers/2023-06-01-preview"
    not valid_azapi_postgresql_flexible_server_geo_backup_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_136: Ensure that PostgreSQL Flexible server enables geo-redundant backups. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLFlexiServerGeoBackupEnabled.py")
}
