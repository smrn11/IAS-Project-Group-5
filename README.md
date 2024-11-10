# IAS Project: Group-5

## AWS Compliance Check Script

This script provides a comprehensive compliance assessment across multiple security and governance areas in an AWS environment. It evaluates key areas: **Compliance**, **Data Protection and Encryption**, **Access Control**, **Incident Response**, and **Governance and Risk Management**. Each area is scored individually based on specific AWS best practices and regulatory standards, providing a score out of 100.

The script uses AWS SDK (`boto3`) to check for compliance in critical services, including **S3**, **EC2**, **IAM**, **CloudTrail**, and **GuardDuty**. Each check verifies whether resources meet required configurations, such as encryption, key rotation, multi-factor authentication (MFA), and policy enforcement. This based on our paper, where each Cloud Vendor is rated on the basis of 5 metrics:
- Compliance with regulatory standards
- Data protection and encryption
- Access control
- Incident response
- Governance and risk management

Each aspect has a total possible score of 5 where 5 individual components are checked. At the end, the script calculates an overall compliance score, that provides a quantified evaluation for the running cloud ecosystem.

### Requirements
- AWS credentials with adequate permissions to perform compliance checks.
- Python with `boto3` installed (`pip install boto3`).

### Usage

Before you run the script, it will ask you for details regarding your AWS account. Open your terminal and run the command `aws configure`. Thiw will prompt your for 4 inputs:
- `AWS ACCESS KEY`:
- `SECRET KEY`:
- `REGION`:
- `OUTPUT FORMAT`:

Once you've configured your AWS credentials successfully, run the script using:
```
python AWS_eval.py
```

After you run the script, depending on the configurations enabled in your AWS ecosystem, you will recieve an output something like this:
```
PS C:\Users\sandr\IAS> python AWS_eval.py
Starting Compliance Check...
Starting Data Protection and Encryption Check...
Starting Access Control Check...
Error in Access Control Check: can't subtract offset-naive and offset-aware datetimes
Starting Incident Response Check...
Starting Governance and Risk Management Check...
Error in Governance Check: An error occurred (InvalidAccessException) when calling the GetEnabledStandards operation: Account 975050316435 is not subscribed to AWS Security Hub

Compliance Score: 20.0
Data Protection and Encryption Score: 80.0
Access Control Score: 40.0
Incident Response Score: 60.0
Governance and Risk Management Score: 45.0
```

## Azure Compliance Check Script

This script performs a comprehensive compliance assessment for an Azure environment, evaluating it across multiple security and governance areas. The assessment includes scores in key areas: **Compliance**, **Data Protection and Encryption**, **Access Control**, **Incident Response**, and **Governance and Risk Management**. Each area is scored based on Azure's best practices, regulatory standards, and compliance frameworks, providing an overall compliance score to gauge the security posture of your Azure environment.

### Key Features

The script uses the Azure SDK (Azure Identity and Azure Management libraries) to perform checks in critical Azure services like Storage, Key Vault, IAM (Azure AD), Monitor, and Security Center. Each check verifies resource configurations and best practices, such as encryption, key rotation, multi-factor authentication (MFA), policy enforcement, and monitoring, based on five main evaluation criteria:

- **Compliance with Regulatory Standards**
- **Data Protection and Encryption**
- **Access Control**
- **Incident Response**
- **Governance and Risk Management**

Each criterion is scored out of a maximum of 5 points, where 5 specific components are verified in each area. At the end, the script provides an overall compliance score out of 100, giving a quantified evaluation of your Azure security ecosystem.

### Requirements

- **Azure Credentials**: A user with sufficient permissions to query resources across the Azure environment.
- **Python and Azure SDK**: Make sure `azure-identity` and `azure-mgmt-*` libraries are installed.

To install the required libraries, run:
```
pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-mgmt-monitor azure-mgmt-keyvault azure-mgmt-security
```

### Usage

Before running the script, ensure you have configured your Azure credentials. You can authenticate using either a service principal or the Azure CLI. For ease of use, it’s recommended to log in using the Azure CLI as follows:
```
az login
```

### Running the Script

Once authenticated, you can execute the script with:

```
python Azure_eval.py
```

The script will automatically check your configurations in the Azure environment, assessing them based on Azure’s best practices and compliance requirements.

### Output

The script’s output will show a breakdown of the scores by category, followed by an overall compliance score. Here’s a sample output:

```
PS C:\Users\username\IAS> python Azure_eval.py
Starting Compliance Check...
Starting Data Protection and Encryption Check...
Starting Access Control Check...
Starting Incident Response Check...
Starting Governance and Risk Management Check...

Compliance Score: 60.0
Data Protection and Encryption Score: 80.0
Access Control Score: 50.0
Incident Response Score: 70.0
Governance and Risk Management Score: 55.0

Overall Compliance Score: 63.0
```

## GCP Compliance Check Script

This script performs a comprehensive compliance assessment for a Google Cloud Platform (GCP) environment, evaluating it across multiple security and governance areas. The assessment includes scores in key areas: **Compliance**, **Data Protection and Encryption**, **Access Control**, **Incident Response**, and **Governance and Risk Management**. Each area is scored based on GCP's best practices, regulatory standards, and compliance frameworks, providing an overall compliance score to gauge the security posture of your GCP environment.

### Key Features

The script uses the GCP SDK (Google Cloud Python Client Libraries) to perform checks in critical GCP services like Cloud Storage, IAM, Cloud Key Management (KMS), Security Command Center, and Logging. Each check verifies resource configurations and best practices, such as encryption, key rotation, multi-factor authentication (MFA), policy enforcement, and monitoring, based on five main evaluation criteria:

- **Compliance with Regulatory Standards**
- **Data Protection and Encryption**
- **Access Control**
- **Incident Response**
- **Governance and Risk Management**

Each criterion is scored out of a maximum of 5 points, where 5 specific components are verified in each area. At the end, the script provides an overall compliance score out of 100, giving a quantified evaluation of your GCP security ecosystem.

### Requirements

- **GCP Credentials**: A user or service account with sufficient permissions to query resources across the GCP environment.
- **Python and GCP SDK**: Make sure `google-auth`, `google-cloud-storage`, `google-cloud-logging`, `google-cloud-iam`, `google-cloud-securitycenter`, and `google-cloud-kms` libraries are installed.

To install the required libraries, run:
```
pip install google-auth google-cloud-storage google-cloud-logging google-cloud-iam google-cloud-securitycenter google-cloud-kms
```
### Usage

Before running the script, ensure you have configured your GCP credentials. You can authenticate by setting up a service account key or by using the gcloud CLI. For ease of use, it’s recommended to authenticate via the gcloud CLI as follows:

```
gcloud auth application-default login
```

### Running the Script

Once authenticated, you can execute the script with:

```
python GCP_eval.py
```

The script will automatically check your configurations in the GCP environment, assessing them based on GCP’s best practices and compliance requirements.

### Output

The script’s output will show a breakdown of the scores by category, followed by an overall compliance score. Here’s a sample output:

```
$ python GCP_eval.py
Starting Compliance Check...
Starting Data Protection and Encryption Check...
Starting Access Control Check...
Starting Incident Response Check...
Starting Governance and Risk Management Check...

Compliance Score: 70.0
Data Protection and Encryption Score: 85.0
Access Control Score: 65.0
Incident Response Score: 75.0
Governance and Risk Management Score: 60.0

Overall Compliance Score: 71.0
```
