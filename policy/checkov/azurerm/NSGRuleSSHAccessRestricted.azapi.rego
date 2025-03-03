
package checkov

import rego.v1

valid_azapi_security_group_rule_ssh_access_restricted(resource) if {
    not contains(resource.body.properties.destinationPortRanges, "22")
    not contains(resource.body.properties.destinationPortRange, "22")
    not contains(resource.body.properties.sourceAddressPrefix, "Internet")
    not contains(resource.body.properties.sourceAddressPrefix, "0.0.0.0/0")
    not contains(resource.body.properties.sourceAddressPrefix, "*")
    resource.body.properties.access == "Deny"
}

deny_CKV_AZURE_10_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.body.properties.direction == "Inbound"
    resource.body.properties.protocol == "Tcp"
    not valid_azapi_security_group_rule_ssh_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_10: Ensure that SSH access is restricted from the internet. Rule %s allows unrestricted SSH access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleSSHAccessRestricted.py", [resource.address])
}
