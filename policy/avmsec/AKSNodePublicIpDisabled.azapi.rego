package avmsec

import rego.v1

invalid_azapi_kubernetes_cluster_node_public_ip_disabled(resource) if {
    resource.values.body.properties.agentPoolProfiles[_].enableNodePublicIP == true
}

deny_AVM_SEC_143 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    invalid_azapi_kubernetes_cluster_node_public_ip_disabled(resource)

    reason := sprintf("avmsec/AVM_SEC_143: Ensure AKS cluster nodes do not have public IP addresses %s: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNodePublicIpDisabled.py", [resource.address])
}
