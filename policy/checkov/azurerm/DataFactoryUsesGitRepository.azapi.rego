
package checkov

import rego.v1

valid_azapi_data_factory_uses_git(resource) if {
  resource.values.properties.githubConfiguration[_].repositoryName != null
}

valid_azapi_data_factory_uses_git(resource) if {
  resource.values.properties.vstsConfiguration[_].repositoryName != null
}

deny_CKV_AZURE_103_azapi contains reason if {
  resource := data.utils.resource(input, "azapi_resource")[_]
  resource.changes.after.type == "Microsoft.DataFactory/factories/2018-06-01"
  not valid_azapi_data_factory_uses_git(resource)

  reason := sprintf("checkov/CKV_AZURE_103: Ensure that Azure Data Factory uses Git repository for source control %s", [resource.address])
}
