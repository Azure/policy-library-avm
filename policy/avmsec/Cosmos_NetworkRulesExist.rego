package avmsec

import rego.v1

#azure_cosmos_db_accounts_should_have_firewall_rules https://github.com/Azure/azure-policy/blob/63d321daccad14c094a0eaaec9c035da2db72c3e/built-in-policies/policyDefinitions/Cosmos%20DB/Cosmos_NetworkRulesExist_Audit.json
deny_AVM_SEC_AZPOLICY_BUILTIN_1 contains reason if {
	res := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_cosmos_db_accounts_do_not_have_firewall_rules(res)

	reason := sprintf("avmsec/AVM_SEC_AZPOLICY_BUILTIN_1: Firewall rules should be defined on your Azure Cosmos DB accounts to prevent traffic from unauthorized sources. Accounts that have at least one IP rule defined with the virtual network filter enabled are deemed compliant. Accounts disabling public access or enabled private endpoint connection are also deemed compliant: https://github.com/Azure/policy-library-avm/blob/main/policy/avmsec/Cosmos_NetworkRulesExist.rego", [res.address])
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_cosmos_db_accounts_do_not_have_firewall_rules(r) if {
	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_publicNetworkAccessEnabledOrOmitted(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_isVritualNetworkFilteredDisabledOrOmitted(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_firewall_rules(r)
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_publicNetworkAccessEnabledOrOmitted(r) if {
	not r.values.public_network_access_enabled == r.values.public_network_access_enabled
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_publicNetworkAccessEnabledOrOmitted(r) if {
	r.values.public_network_access_enabled == true
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_isVritualNetworkFilteredDisabledOrOmitted(r) if {
	not r.values.is_virtual_network_filter_enabled == r.values.is_virtual_network_filter_enabled
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_isVritualNetworkFilteredDisabledOrOmitted(r) if {
	not r.values.is_virtual_network_filter_enabled
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_ip_range_filter(r) if {
	not r.values.ip_range_filter == r.values.ip_range_filter
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_ip_range_filter(r) if {
	count({x | x := r.values.ip_range_filter[_]}) == 0
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_private_endpoint_connection(r) if {
    not AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_with_private_endpoint_connection(r)
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_with_private_endpoint_connection(r) if {
	cosmosdb_account_id := r.values.id
	private_endpoint := data.utils.resource(input, "azurerm_private_endpoint")[_]
	private_endpoint.private_service_connection[0].private_connection_resource_id == cosmosdb_account_id
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_with_private_endpoint_connection(r) if {
	private_endpoint_config := data.utils.resource_configuration(input)[_]
	private_endpoint_config.type == "azurerm_private_endpoint"

	data.utils.arraycontains([ sprintf("%s%s", [private_endpoint_config.module_prefix, ref]) | some ref in private_endpoint_config.expressions.private_service_connection[_].private_connection_resource_id.references], sprintf("%s.%s", [r.address, "id"]))
}

AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_firewall_rules(r) if {
	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_ip_range_filter(r)
	AVM_SEC_AZPOLICY_BUILTIN_1_azurerm_no_private_endpoint_connection(r)
}
