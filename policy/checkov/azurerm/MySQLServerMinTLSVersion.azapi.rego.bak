
package checkov

import rego.v1

valid_azapi_mysql_server_min_tls_version(resource) if {
    resource.body.properties.sslMinimalTlsVersionEnforced == "TLS1_2"
}

deny_CKV_AZURE_54_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.DBforMySQL/flexibleServers/2023-12-30"
    not valid_azapi_mysql_server_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_54: Ensure MySQL is using the latest version of TLS encryption. Expected TLS1_2, got %v. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLServerMinTLSVersion.py", [resource.body.properties.sslMinimalTlsVersionEnforced])
}
