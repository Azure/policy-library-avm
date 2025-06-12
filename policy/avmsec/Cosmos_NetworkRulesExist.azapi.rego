package avmsec

import rego.v1


deny_AVM_SEC_AZPOLICY_BUILTIN_1 contains reason if {
	res := data.utils.resource(input, "azapi_resource")[_]
	AVM_SEC_AZPOLICY_BUILTIN_1_cosmos_db_accounts_do_not_have_firewall_rules(res)
	reason := sprintf("avmsec/AVM_SEC_AZPOLICY_BUILTIN_1: Firewall rules should be defined on your Azure Cosmos DB accounts to prevent traffic from unauthorized sources. Accounts that have at least one IP rule defined with the virtual network filter enabled are deemed compliant. Accounts disabling public access are also deemed compliant: https://github.com/Azure/policy-library-avm/blob/main/policy/avmsec/Cosmos_NetworkRulesExist.azapi.rego", [res.address])
}

AVM_SEC_AZPOLICY_BUILTIN_1_cosmos_db_accounts_do_not_have_firewall_rules(r) if {
	data.utils.is_azure_type(r.values, "Microsoft.DocumentDB/databaseAccounts")
	AVM_SEC_AZPOLICY_BUILTIN_1_publicNetworkAccessEnabledOrOmitted(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_isVritualNetworkFilteredDisabledOrOmitted(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_no_firewall_rules(r)
}

AVM_SEC_AZPOLICY_BUILTIN_1_publicNetworkAccessEnabledOrOmitted(r) if {
	not r.values.properties.publicNetworkAccess == r.values.properties.publicNetworkAccess
}

AVM_SEC_AZPOLICY_BUILTIN_1_publicNetworkAccessEnabledOrOmitted(r) if {
	r.values.properties.publicNetworkAccess == "Enabled"
}

AVM_SEC_AZPOLICY_BUILTIN_1_isVritualNetworkFilteredDisabledOrOmitted(r) if {
	not r.values.properties.isVirtualNetworkFilterEnabled == r.values.properties.isVirtualNetworkFilterEnabled
}

AVM_SEC_AZPOLICY_BUILTIN_1_isVritualNetworkFilteredDisabledOrOmitted(r) if {
	r.values.properties.isVirtualNetworkFilterEnabled == false
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_rules(r) if {
	not r.values.properties.ipRules == r.values.properties.ipRules
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_rules(r) if {
	count({x | x := r.values.properties.ipRules[_]}) == 0
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_range_filter(r) if {
	not r.values.properties.ipRangeFilter == r.values.properties.ipRangeFilter
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_range_filter(r) if {
	r.values.properties.ipRangeFilter == ""
}

AVM_SEC_AZPOLICY_BUILTIN_1_approved(r, x) if {
	x.privateLinkServiceConnectionState.status == "Approved"
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_private_endpoint_connections(r) if {
	count({x | x := r.values.properties.privateEndpointConnections[_]; AVM_SEC_AZPOLICY_BUILTIN_1_approved(r, x)}) < 1
}

AVM_SEC_AZPOLICY_BUILTIN_1_no_firewall_rules(r) if {
	AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_rules(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_no_ip_range_filter(r)

	AVM_SEC_AZPOLICY_BUILTIN_1_no_private_endpoint_connections(r)
}
