package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer(resource) if {
    count(resource.values.body.properties.outboundRules) == 0
}

valid_azapi_use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer(resource) if {
    not resource.values.body.properties.outboundRules == resource.values.body.properties.outboundRules
}

deny_use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/loadBalancers")
    not valid_azapi_use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer: '%s' `azapi_resource` must not config `outboundRules. Outbound rules for Standard Public Load Balancer involve manual port allocation for backend pools, limiting scalability and risk of SNAT port exhaustion. NAT Gateway is recommended for its dynamic scaling and secure internet connectivity.: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads", [resource.address])
}