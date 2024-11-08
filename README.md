# IAS Project: Group-5

### AWS Compliance Check Script

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
```bash
python AWS_eval.py
```

After you run the script, depending on the configurations enabled in your AWS ecosystem, you will recieve an output something like this:
```
PS C:\Users\sandr\IAS> python eval.py
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






