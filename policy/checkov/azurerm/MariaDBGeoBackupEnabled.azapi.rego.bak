
package checkov

import rego.v1

valid_azapi_mariadb_server_geo_backup_enabled(resource) if {
    resource.values.body.properties.geoRedundantBackup == true
}

deny_CKV_AZURE_129_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.changes.after.type == "Microsoft.DBforMariaDB/servers"
    not valid_azapi_mariadb_server_geo_backup_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_129: Ensure that MariaDB server enables geo-redundant backups. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBGeoBackupEnabled.py")
}
