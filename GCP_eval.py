from google.cloud import logging_v2, securitycenter, storage, compute_v1, iam_v1
from google.auth import default
from datetime import datetime, timedelta

credentials, project_id = default()
log_client = logging_v2.Client()
security_center_client = securitycenter.SecurityCenterClient()
storage_client = storage.Client()
compute_client = compute_v1.InstancesClient()
iam_client = iam_v1.IAMClient()

compliance_score = 0
data_protection_score = 0
access_control_score = 0
incident_response_score = 0
governance_score = 0

try:
    print("Starting Compliance Check...")
    security_sources = security_center_client.list_sources(request={"parent": f"organizations/{project_id}"})
    major_standards = ['CIS', 'NIST', 'ISO 27001', 'PCI DSS', 'FedRAMP']
    compliance_score += sum(1 for source in security_sources if any(standard in source.display_name for standard in major_standards))

    log_metrics = log_client.list_metrics()
    if any(metric for metric in log_metrics):
        compliance_score += 1

    findings = security_center_client.list_findings(
        request={"parent": f"projects/{project_id}"}
    )
    if findings:
        compliance_score += 1

    if len(storage_client.list_buckets()) > 1:
        compliance_score += 1
except Exception as e:
    print("Error in Compliance Check:", e)

try:
    print("Starting Data Protection and Encryption Check...")
    buckets = storage_client.list_buckets()
    encrypted_buckets = all(bucket.encryption for bucket in buckets)
    if encrypted_buckets:
        data_protection_score += 1

    instances = compute_client.aggregated_list(project=project_id)
    cmek_instances = all(
        instance.disks[0].disk_encryption_key.kms_key_name for _, instance_list in instances for instance in instance_list.instances if instance.disks
    )
    if cmek_instances:
        data_protection_score += 1

    ssl_policies = compute_client.ssl_policies().list(project=project_id)
    tls_enabled = all('TLS_1_2' in policy.min_tls_version for policy in ssl_policies)
    if tls_enabled:
        data_protection_score += 1

except Exception as e:
    print("Error in Data Protection Check:", e)

try:
    print("Starting Access Control Check...")
    policies = iam_client.list_roles(request={"parent": f"projects/{project_id}"})
    if all("owner" not in role.name.lower() for role in policies):
        access_control_score += 1

    users = iam_client.list_service_accounts(request={"name": f"projects/{project_id}"})
    if users:
        access_control_score += 1

    service_accounts = iam_client.list_service_accounts(request={"name": f"projects/{project_id}"})
    rotated_keys = all((datetime.utcnow() - key.valid_after_time.timestamp()).days < 90 for account in service_accounts for key in iam_client.list_service_account_keys(request={"name": account.name}).keys)
    if rotated_keys:
        access_control_score += 1

except Exception as e:
    print("Error in Access Control Check:", e)

try:
    print("Starting Incident Response Check...")
    detectors = list(security_center_client.list_sources(request={"parent": f"projects/{project_id}"}))
    if detectors:
        incident_response_score += 1

    metrics = log_client.list_metrics()
    if any(metrics):
        incident_response_score += 1

    findings = security_center_client.list_findings(request={"parent": f"projects/{project_id}"})
    if any(findings):
        incident_response_score += 1

except Exception as e:
    print("Error in Incident Response Check:", e)

try:
    print("Starting Governance and Risk Management Check...")
    security_settings = security_center_client.list_sources(request={"parent": f"organizations/{project_id}"})
    if security_settings:
        governance_score += 1

    log_entries = log_client.list_entries(order_by=logging_v2.DESCENDING, page_size=10)
    if any(log_entries):
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
