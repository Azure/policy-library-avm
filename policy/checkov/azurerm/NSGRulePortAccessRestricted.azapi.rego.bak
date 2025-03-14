package checkov

import rego.v1

# Rule CKV_AZURE_203

INTERNET_ADDRESSES := ["*", "0.0.0.0", "<nw>/0", "/0", "internet", "any"]

valid_azurerm_network_security_rule_203(resource, port) if {
    not allow_inbound_access_from_internet(resource, port)
}

allow_inbound_access_from_internet(resource, port) if {
    access := lower(resource.access)
    direction := lower(resource.direction)
    protocol := lower(resource.protocol)

    access == "allow"
    direction == "inbound"
    protocol == "tcp" || protocol == "*"

    # Check destination port
    destination_port_valid(resource, port)

    # Check source address
    source_address_from_internet(resource)
}

destination_port_valid(resource, port) if {
    (resource.destination_port_range != null && is_port_in_range(resource.destination_port_range, port)) ||
    (resource.destination_port_ranges != null && any(resource.destination_port_ranges, func(range) {is_port_in_range(range, port)}))
}

is_port_in_range(port_range, port) if {
    re_match("^\\d+-\\d+$", port_range)
    start := to_number(split(port_range, "-")[0])
    end := to_number(split(port_range, "-")[1])
    port >= start
    port <= end
}

is_port_in_range(port_range, port) if {
    port_range == to_string(port) || port_range == "*"
}

source_address_from_internet(resource) if {
    (resource.source_address_prefix != null && lower(resource.source_address_prefix) == INTERNET_ADDRESSES[_]) ||
    (resource.source_address_prefixes != null && any(resource.source_address_prefixes, func(prefix) {lower(prefix) == INTERNET_ADDRESSES[_]}))
}

deny_CKV_AZURE_203 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    port := 22  #Fixed port to check
    not valid_azurerm_network_security_rule_203(resource, port)

    reason := sprintf("checkov/CKV_AZURE_203: Network Security Rule allows port 22 access from internet on %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [resource.address])
}

deny_CKV_AZURE_203 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_group")[_]
    # assuming the check should also apply to NSGs, but NSGs don't have the same attributes directly
    # need to iterate through the security rules within the NSG
    rules := resource.security_rule
    some i
    rule := rules[i]
    port := 22
    not valid_azurerm_network_security_rule_203(rule, port)
    reason := sprintf("checkov/CKV_AZURE_203: Network Security Group allows port 22 access from internet on %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [resource.address])
}

# azapi resource
valid_azapi_network_security_rule_203(resource, port) if {
    not allow_inbound_access_from_internet_azapi(resource, port)
}

allow_inbound_access_from_internet_azapi(resource, port) if {
    access := lower(resource.properties.access)
    direction := lower(resource.properties.direction)
    protocol := lower(resource.properties.protocol)

    access == "allow"
    direction == "inbound"
    protocol == "tcp" || protocol == "*"

    # Check destination port
    destination_port_valid_azapi(resource, port)

    # Check source address
    source_address_from_internet_azapi(resource)
}

destination_port_valid_azapi(resource, port) if {
    (resource.properties.destinationPortRange != null && is_port_in_range(resource.properties.destinationPortRange, port)) ||
    (resource.properties.destinationPortRanges != null && any(resource.properties.destinationPortRanges, func(range) {is_port_in_range(range, port)}))
}

source_address_from_internet_azapi(resource) if {
    (resource.properties.sourceAddressPrefix != null && lower(resource.properties.sourceAddressPrefix) == INTERNET_ADDRESSES[_]) ||
    (resource.properties.sourceAddressPrefixes != null && any(resource.properties.sourceAddressPrefixes, func(prefix) {lower(prefix) == INTERNET_ADDRESSES[_]}))
}

deny_CKV_AZURE_203_azapi contains reason if {
    resource_changes := input.resource_changes[_]
    resource_changes.type == "azapi_resource"
    resource := resource_changes.changes.after
    rules := resource.body.properties.securityRules
    some i
    rule := rules[i].properties
    port := 22 # Fixed port to check
    not valid_azapi_network_security_rule_203(rule, port)
    reason := sprintf("checkov/CKV_AZURE_203: Network Security Rule allows port 22 access from internet on %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [resource_changes.address])
}
