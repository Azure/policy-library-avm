package checkov

import rego.v1

valid_azapi_frontdoor_firewall_policy_cve_2021_44228(resource) if {
    managed_rules := resource.body.properties.managedRules.managedRuleSets
    some(managed_rules)
    managed_rule := managed_rules[_]
    managed_rule.ruleSetType == "DefaultRuleSet" || managed_rule.ruleSetType == "Microsoft_DefaultRuleSet"
    rule_overrides := managed_rule.ruleGroupOverrides
    some(rule_overrides)
    rule_override := rule_overrides[_]
    rule_override.ruleGroupName == "JAVA"
    rules := rule_override.rules
    some(rules)
    rule := rules[_]
    rule.ruleId == "944240"
    rule.enabledState == "Enabled"
    rule.action == "Block" || rule.action == "Redirect"
}

deny_CKV_AZURE_133_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Network/frontDoorWebApplicationFirewallPolicies/2020-04-01"
    not valid_azapi_frontdoor_firewall_policy_cve_2021_44228(resource)
    reason := sprintf("checkov/CKV_AZURE_133: Ensure Front Door WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontDoorWAFACLCVE202144228.py")
}
