![CVEDataLake](https://i.imgur.com/9qfpYjc.png)

## Project Overview

CVEDataLake is a cloud-based project that automates the ingestion, storage, and querying of the Common Vulnerabilities and Exposures (CVE) dataset. It uses AWS services like S3, Glue, and Athena, along with Infrastructure as Code (IaC) through Ansible, to streamline deployment and enable efficient data analysis.

## Components

- **Rocky Linux**: Provides a stable and secure environment for running the automation and orchestration workflows
- **S3**: Serves as the storage solution for fetched CVE data from the NVD
- **AWS Glue**: Used to define schemas and configure Glue tables for organizing and structuring the data
- **AWS Athena**: Provides SQL querying capabilities to analyze the data and generate JSON reports
- **Ansible**: Automates the setup of infrastructure and the generation of reports for repeatability and efficiency
- **Python**: Facilitates data fetching, processing, and integration with AWS services through scripts and libraries

## Use Case

CVEDataLake's flexibility makes it a valuable tool for Security Operations Centers (SOCs) and vulnerability management workflows. The JSON files generated from SQL queries can be used for various purposes, such as:

- **Trend Analysis**: Identify patterns in vulnerabilities over time to prioritize mitigation.
- **Integration**: Incorporate JSON data into dashboards or visualization tools.
- **Automation**: Feed JSON data into automated security workflows or vulnerability scanners.
- **Custom Reports**: Generate tailored reports for compliance audits or team-specific needs.

## Versions

| Component         | Version  | Component         | Version  |
|-------------------|----------|-------------------|----------|
| Rocky Linux       | 9.4      | Python            | 3.9.21   |
| AWS CLI           | Latest   | Pip               | 21.3.1   |
| Ansible           | 2.15     | Botocore          | 1.31.0   |
| Community.general | 9.0      | Boto3             | 1.28.0   |
| Amazon.aws        | 9.0      | Requests          | 2.28.2   | 

 

## Prerequisites

- **Rocky Linux VM**
  - Fresh installation of Rocky Linux
  - Allocate sufficient resources: **2 CPUs, 4GB RAM**
- **AWS Account**
   - An AWS account with provisioned access-key and secret-key

## Environment Setup

**Run the following to setup our VM:**
```bash
cd
dnf install -y git ansible-core
git clone -b feature https://github.com/Thuynh808/CVEDataLake
cd CVEDataLake 
ansible-galaxy collection install -r requirements.yaml -vv
```
  Command Breakdown:
  - Navigates to home directory
  - Installs `Git` and `Ansible`
  - Clone repository
  - Navigates to project directory
  - Install required Ansible Collections

## Define Variables

**Update variables with proper values for file: `vars.yaml`**
```bash
vim vars.yaml
```
```bash
aws_access_key_id: "<your-access-key-id>"
aws_secret_access_key: "<your-secret-access-key>"
defaultregion: "us-east-1"
email_endpoint: "<your-email>"
bucket_name: "<your-bucket-name>"
glue_database_name: "glue_cve_data_lake"
glue_table_name: "cve_records"
```
**Set permissions to secure file**
```bash
chmod 0600 vars.yaml 
```
> Note: Keep the sensitive file local. Add to `.gitignore` if uploading to GitHub
<br>  

## Deployment and Testing

**Run Playbook:**
```bash
ansible-playbook setup_infra.yaml -vv
```
  The `setup_infra.yaml` playbook will:
  - Install and upgrade system packages
  - Install `pip` modules with required versions
  - Download, unzip and install `AWS CLI`
  - Configure `AWS CLI`
  - Create S3 bucket
  - Set up a `Glue` database to organize CVE vulnerability data
  - Run Python scripts to:
    - Send GET requests to the NVD API to fetch the CVE dataset
    - Upload the data to the `S3` bucket in batches for efficient storage
    - Create a Glue table and define schemas for structured querying
    - Set up an `Athena` workgroup for executing SQL queries on the data

**Confirm Successful Execution:**
```bash
ansible --version
python3 --version
pip --version
pip list | egrep "boto3|botocore|requests" 
aws configure list
aws sts get-caller-identity
aws s3 ls
aws s3 ls s3://cve-data-lake-thuynh/ #Change to your bucket name
aws glue get-database --name glue_cve_data_lake
aws glue get-tables --database-name glue_cve_data_lake | head
aws athena list-work-groups | head
```

<details close>
  <summary> <h4>Image Results</h4> </summary>
    
![CVEDataLake](https://i.imgur.com/9qfpYjc.png)
  
  - **System dependencies**: (curl, unzip, python3, python3-pip) are installed
  - **Python libraries**: (boto3, botocore, python-dotenv, requests) are installed with required versions
  - **AWS CLI**: credentials and region are properly configured
  - **IAM identity**: is correctly authenticated via AWS CLI, confirming access to the AWS account
  - **S3 bucket**: exists and is accessible through the CLI
  - **SNS topic**: is successfully created, and its ARN matches the expected configuration
  </details>

---
```bash
ansible-playbook sample-reports.yaml -vv
```
### Now we need to log in to email account and confirm subscription

<details close>
  <summary> <h4>Images Results</h4> </summary>
    
![Weather-Dashboard-Automation](https://i.imgur.com/nJw3q63.png)

  - **Click and confirm subscription**
    
![Weather-Dashboard-Automation](https://i.imgur.com/qaG7Akb.png)
  </details>

---

**Run Final Playbook:**
```bash
ansible-playbook weather_lambda_eventbridge.yaml -vv
```
  The `weather_lambda_eventbridge.yaml` playbook will:
  - Create IAM `lambda-execution-role` to provide permissions to execute `Lambda` function
  - Add IAM execution role ARN variable to myvars.yaml
  - Generate a custom IAM policy and attach to our `lambda-execution-role`
  - Compress the `Lambda` python script
  - Create `Lambda` function from script and attach the IAM role
  - Append `Lambda` variables to myvars.yaml
  - Enable `EventBridge` notifications on `S3` bucket
  - Generate rule in `EventBridge` for newly created objects in `S3`
  - Set `EventBridge` target to invoke the `Lambda` function when event is triggered
  - Automate a daily cron job to fetch weather data and upload it to `S3` using a Python script

**Confirm Successful Execution:**

```bash
aws lambda list-functions
aws events list-rules 
crontab -l
```
<details close>
  <summary> <h4>Image Results</h4> </summary>
    
![Weather-Dashboard-Automation](https://i.imgur.com/90vYwtb.png)
![Weather-Dashboard-Automation](https://i.imgur.com/ZocVy92.png)

  - **Lambda Function**: Verify function name and ARN are correct; SNS Topic ARN is properly set as environment variable
  - **EventBridge Rule**: Confirm state is `ENABLED` and event pattern is set to trigger when an object is created in S3
  - **Cron Job**: a daily cron job exists to run the Python script (weather_data_aggregator.py) at the correct time (0 8 * * *)
  </details>

---

### Excellent! Now for a demo, let's manually test our Weather Dashboard!

**Run:**
```bash
python src/weather_data_aggregator.py
```
<details close>
  <summary> <h4>See results</h4> </summary>
    
![Weather-Dashboard-Automation](https://i.imgur.com/lHZRlOe.png) 

![Weather-Dashboard-Automation](https://i.imgur.com/ID2DT3y.png)

**Awesome! We can confirm the data is saved to S3 which triggered our workflow to finally deliver the notification to our email!**
  </details>

## Challenges and Solutions

- Versioning Issue with Lambda ARN: Resolved by dynamically extracting the base ARN without version numbers
- Policy Propagation Error: Added a "pause" module after creating IAM policies to ensure EventBridge permissions were applied
- Dynamic Variables in Ansible: Used set_fact and lineinfile modules to dynamically update variable file
- Conditional Task Execution: Ensured the AWS CLI installation only runs when not already present using "when" conditions
- S3 Event Configuration Error: Properly enabled EventBridge for S3 bucket events to trigger Lambda

## Conclusion

Let's GO!! I thoroughly enjoyed building the Weather-Dashboard-Automation project. I've gained more hands-on experience with AWS services along with Ansible automation and IaC principles. To see these services work seamlessly to create a functional, scalable solution for daily weather notifications was such a thrill!
