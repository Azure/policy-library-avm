package checkov

import rego.v1

valid_azapi_web_application_firewall_policy_enabled(resource) if {
    resource.changes.after.body.properties.policySettings.state == "Enabled"
}

deny_CKV_AZURE_122_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.address == "azurerm_web_application_firewall_policy.example"
    not valid_azapi_web_application_firewall_policy_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_122: Ensure that Application Gateway uses WAF in \"Detection\" or \"Prevention\" modes %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWUseWAFMode.py", [resource.address])
}
