# [Azure-Proactive-Resiliency-Library-v2](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/)

* `Microsoft.Compute/virtualMachines`

`legacy_virtual_machine_not_allowed`
[`migrate_vm_using_availability_sets_to_vmss_flex`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex)
[`mission_critical_virtual_machine_should_use_premium_or_ultra_disks`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#mission-critical-workloads-should-consider-using-premium-or-ultra-disks)
[`mission_critical_virtual_machine_should_use_zone`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#deploy-vms-across-availability-zones)

* `Microsoft.ContainerService/managedClusters`

[`configure_aks_default_node_pool_zones`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones)

* `Microsoft.DocumentDB/databaseAccounts`

[`configure_cosmosdb_account_continuous_backup_mode`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode)

* `Microsoft.Network/applicationGateways`

[`migrate_to_application_gateway_v2`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2)
[`deploy_application_gateway_in_a_zone_redundant_configuration`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration)

* `Microsoft.Network/loadBalancers`

[`use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads)
[`use_resilient_load_lalancer_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku)

* `Microsoft.Network/publicIPAddresses`

[`public_ip_use_standard_sku_and_zone_redundant_ip`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable)

* `Microsoft.Network/virtualNetworkGateways`

[`virtual_network_gateway_use_zone_redundant_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#use-zone-redundant-expressroute-gateway-skus)

* `Microsoft.DBforMySQL/flexibleServers`

[`mysql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy)
[`mysql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)

* `Microsoft.DBforPostgreSQL/flexibleServers`

[`postgresql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)
[`postgresql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy)

* `Microsoft.Storage/storageAccounts`

[`storage_accounts_are_zone_or_region_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Storage/storageAccounts/#ensure-that-storage-accounts-are-zone-or-region-redundant)