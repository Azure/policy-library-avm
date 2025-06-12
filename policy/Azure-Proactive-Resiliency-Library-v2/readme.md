# [Azure-Proactive-Resiliency-Library-v2](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/)

The following APRL checks have been implemented. Use the name's below when requesting exceptions. Each name links to the relevant [APRL](https://aka.ms/aprl) documentation.


* `Microsoft.ApiManagement/service` or `azurerm_api_management`
    - [`api_management_services_are_premium_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#migrate-api-management-services-to-premium-sku-to-support-availability-zones)
    - [`enable_zone_redundancy_for_api_management`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#enable-availability-zones-on-premium-api-management-instances)

* `Microsoft.Cache/redis` or `azurerm_redis_cache`

    - [`enable_zone_redundancy_for_azure_cache_for_redis`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Cache/Redis/#enable-zone-redundancy-for-azure-cache-for-redis)

* `Microsoft.Compute/virtualMachines` or `azurerm_linux_virtual_machine` or `azurerm_windows_virtual_machine`

    - `legacy_virtual_machine_not_allowed`
    - [`migrate_vm_using_availability_sets_to_vmss_flex`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex)
    - [`mission_critical_virtual_machine_should_use_premium_or_ultra_disks`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#mission-critical-workloads-should-consider-using-premium-or-ultra-disks)
    - [`mission_critical_virtual_machine_should_use_zone`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#deploy-vms-across-availability-zones)
    - [`virtual_machines_should_use_managed_disks`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#use-managed-disks-for-vm-disks)

* `Microsoft.Compute/virtualMachineScaleSet` or `azurerm_orchestrated_virtual_machine_scale_set`
    - [`virtual_machine_scaleset_disable_force_strictly_even_zone_balancing`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#disable-force-strictly-even-balance-across-zones-to-avoid-scale-in-and-out-fail-attempts)
    - [`virtual_machine_scaleset_enable_automatic_repair`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#enable-automatic-repair-policy-on-azure-virtual-machine-scale-sets)
    - [`virtual_machine_scaleset_orchestration_mode_flexible`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-with-flex-orchestration-mode-instead-of-uniform)
    - [`virtual_machine_scaleset_zonal_support`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-across-availability-zones-with-vmss-flex)

* `Microsoft.ContainerService/managedClusters` or `azurerm_kubernetes_cluster`

    - [`aks_enable_cluster_autoscaler`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#enable-the-cluster-auto-scaler-on-an-existing-cluster)
    - [`aks_sku_standard_or_premium`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#update-aks-tier-to-standard-or-premium)
    - [`aks_system_pool_min_node_count`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-system-nodepool-count)
    - [`aks_user_pool_min_node_count`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#configure-user-nodepool-count)
    - [`configure_aks_default_node_pool_zones`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones)

* `Microsoft.DBforMySQL/flexibleServers` or `azurerm_mysql_flexible_server`

    - [`mysql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)
    - [`mysql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy)    

* `Microsoft.DBforPostgreSQL/flexibleServers` or `azurerm_postgresql_flexible_server`

    - [`postgresql_flexible_server_custom_maintenance_window_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-custom-maintenance-schedule)
    - [`postgresql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)    
    - [`postgresql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy)

* `Microsoft.DocumentDB/databaseAccounts` or `azurerm_cosmosdb_account`

    - [`configure_cosmosdb_account_continuous_backup_mode`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode)
    - [`configure_cosmosdb_account_enable_automatic_failover`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#enable-service-managed-failover-for-multi-region-accounts-with-single-write-region)

* `Microsoft.EventHub/namespaces` or `azurerm_eventhub_namespace`

    - [`eventhub_namespace_enable_auto_inflate`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#enable-auto-inflate-on-event-hub-standard-tier)
    - [`eventhub_namespace_zonal_support`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#ensure-zone-redundancy-is-enabled-in-supported-regions)

* `Microsoft.Network/applicationGateways` or `azurerm_application_gateway`

    - [`application_gateway_ensure_autoscale_feature_has_been_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#ensure-autoscale-feature-has-been-enabled)
    - [`deploy_application_gateway_in_a_zone_redundant_configuration`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration)
    - [`migrate_to_application_gateway_v2`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2)    

* `Microsoft.Network/azureFirewalls` or `azurerm_firewall`

    - [`deploy_azure_firewall_across_multiple_availability_zones`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/azureFirewalls/#deploy-azure-firewall-across-multiple-availability-zones)

* `Microsoft.Network/loadBalancers` or `azurerm_lb`

    - [`use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads)
    - [`use_resilient_load_balancer_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku)

* `Microsoft.Network/publicIPAddresses` or `azurerm_public_ip`

    - [`public_ip_use_standard_sku_and_zone_redundant_ip`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable)

* `Microsoft.Network/virtualNetworkGateways` or `azurerm_virtual_network_gateway`

    - [`virtual_network_gateway_use_zone_redundant_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#use-zone-redundant-expressroute-gateway-skus)
    - [`virtual_network_gateway_vpn_active_active`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#enable-active-active-vpn-gateways-for-redundancy)

* `Microsoft.Storage/storageAccounts` or `azurerm_storage_account`

    - [`storage_accounts_are_zone_or_region_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Storage/storageAccounts/#ensure-that-storage-accounts-are-zone-or-region-redundant)

* `Microsoft.Web/serverfarms` or `azurerm_service_plan`

    - [`migrate_service_plan_to_availability_zone_support`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#migrate-app-service-to-availability-zone-support)
    - [`service_plan_use_standard_or_premium_tier`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Web/serverFarms/#use-standard-or-premium-tier)