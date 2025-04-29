package Azure_Proactive_Resiliency_Library_v2

import rego.v1
#VPN and Active-Active
valid_azurerm_virtual_network_gateway_vpn_active_active(resource) if {
   resource.values.type == "Vpn"
   resource.values.active_active == true
}
#OR ExpressRoute
valid_azurerm_virtual_network_gateway_vpn_active_active(resource) if {
   resource.values.type == "ExpressRoute"
}

deny_virtual_network_gateway_vpn_active_active contains reason if {
    resource := data.utils.resource(input, "azurerm_virtual_network_gateway")[_]
    not valid_azurerm_virtual_network_gateway_vpn_active_active(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_network_gateway_vpn_active_active: '%s' `azurerm_virtual_network_gateway` of `type` `Vpn` should have `active_active` set to `true`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#enable-active-active-vpn-gateways-for-redundancy", [resource.address])
}