from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from datetime import datetime

credential = DefaultAzureCredential()
subscription_id = "<Your Subscription ID>"

kv_client = KeyVaultManagementClient(credential, subscription_id)
monitor_client = MonitorClient(credential, subscription_id)
network_client = NetworkManagementClient(credential, subscription_id)
security_center = SecurityCenter(credential, subscription_id)
resource_client = ResourceManagementClient(credential, subscription_id)
compute_client = ComputeManagementClient(credential, subscription_id)
storage_client = StorageManagementClient(credential, subscription_id)

compliance_score = 0
data_protection_score = 0
access_control_score = 0
incident_response_score = 0
governance_score = 0

try:
    print("Starting Compliance Check...")
    security_standards = security_center.compliance_assessments.list()
    major_standards = ['ISO 27001', 'SOC 2', 'PCI DSS', 'NIST', 'FedRAMP']
    compliance_score += sum(1 for assessment in security_standards if assessment.compliance_standard in major_standards)

    policies = resource_client.policy_definitions.list()
    if policies:
        compliance_score += 1

    reports = security_center.regulatory_compliance_standards.list()
    if reports:
        compliance_score += 1

    nsgs = network_client.network_security_groups.list_all()
    if nsgs:
        compliance_score += 1
except Exception as e:
    print("Error in Compliance Check:", e)

try:
    print("Starting Data Protection and Encryption Check...")
    storage_accounts = storage_client.storage_accounts.list()
    if all(account.encryption.services for account in storage_accounts):
        data_protection_score += 1

    key_vaults = kv_client.vaults.list()
    if key_vaults:
        data_protection_score += 1

    vms = compute_client.virtual_machines.list_all()
    encrypted_vms = all(vm.storage_profile.os_disk.encryption_settings.enabled for vm in vms if vm.storage_profile.os_disk.encryption_settings)
    if encrypted_vms:
        data_protection_score += 1

    gateways = network_client.application_gateways.list_all()
    tls_enabled = all(gateway.ssl_policy.policy_type == 'Predefined' and gateway.ssl_policy.policy_name == 'AppGwSslPolicy20170401' for gateway in gateways if gateway.ssl_policy)
    if tls_enabled:
        data_protection_score += 1

except Exception as e:
    print("Error in Data Protection Check:", e)

try:
    print("Starting Access Control Check...")
    roles = resource_client.role_assignments.list()
    if all('owner' not in role.role_definition_id for role in roles):
        access_control_score += 1

    access_policies = security_center.security_contact_policies.list()
    if access_policies:
        access_control_score += 1

    credentials = monitor_client.diagnostics.list()
    rotated_keys = all((datetime.now() - credential.creation_time).days < 90 for credential in credentials)
    if rotated_keys:
        access_control_score += 1

    inactive_users = [user for user in roles if user.principal_type == 'User' and not user.last_sign_in]
    if not inactive_users:
        access_control_score += 1
except Exception as e:
    print("Error in Access Control Check:", e)

try:
    print("Starting Incident Response Check...")
    alerts = security_center.alerts.list()
    if alerts:
        incident_response_score += 1

    alarms = monitor_client.alert_rules.list_by_subscription()
    if alarms:
        incident_response_score += 1

    alert_config = security_center.regulatory_compliance_standards.list()
    if alert_config:
        incident_response_score += 1
except Exception as e:
    print("Error in Incident Response Check:", e)

try:
    print("Starting Governance and Risk Management Check...")
    enabled_standards = security_center.compliance_assessments.list()
    if enabled_standards:
        governance_score += 1

    compliant_nsgs = all(nsg.security_rules for nsg in nsgs)
    if compliant_nsgs:
        governance_score += 1

    log_groups = monitor_client.activity_logs.list()
    if log_groups:
        governance_score += 1
except Exception as e:
    print("Error in Governance Check:", e)

compliance_total_score = (compliance_score / 5) * 100
data_protection_total_score = (data_protection_score / 5) * 100
access_control_total_score = (access_control_score / 5) * 100
incident_response_total_score = (incident_response_score / 5) * 100
governance_total_score = (governance_score / 5) * 100

overall_score = (compliance_total_score + data_protection_total_score +
                 access_control_total_score + incident_response_total_score +
                 governance_total_score) / 5

print("\nCompliance Score:", compliance_total_score)
print("Data Protection and Encryption Score:", data_protection_total_score)
print("Access Control Score:", access_control_total_score)
print("Incident Response Score:", incident_response_total_score)
print("Governance and Risk Management Score:", governance_total_score)
print("\nOverall Compliance Score:", overall_score)
