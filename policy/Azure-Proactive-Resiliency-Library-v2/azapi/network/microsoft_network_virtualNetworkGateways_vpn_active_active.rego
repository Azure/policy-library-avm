package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_virtual_network_gateway_vpn_active_active(resource) if {
   #vpn + active-active
   resource.values.body.properties.gatewayType == "Vpn"
   resource.values.body.properties.activeActive == true
}
#OR
valid_azapi_virtual_network_gateway_vpn_active_active(resource) if {
   #expressroute 
   resource.values.body.properties.gatewayType == "ExpressRoute"
}
#OR
valid_azapi_virtual_network_gateway_vpn_active_active(resource) if {
   #localGateway
   resource.values.body.properties.gatewayType == "LocalGateway"
}

deny_virtual_network_gateway_vpn_active_active contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/virtualNetworkGateways")
    not valid_azapi_virtual_network_gateway_vpn_active_active(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_network_gateway_vpn_active_active: '%s' `azapi_resource` of `gatewayType` `Vpn` should have `ActiveActive` set to `true`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#enable-active-active-vpn-gateways-for-redundancy", [resource.address])
}