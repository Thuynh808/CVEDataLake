![CVEDataLake](https://i.imgur.com/eaeJcP2) 

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

## Deployment

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
aws s3 ls s3://cve-data-lake-thuynh/ #Change "cve-data-lake-thuynh" to your bucket name
aws glue get-database --name glue_cve_data_lake
aws glue get-tables --database-name glue_cve_data_lake | head
aws athena list-work-groups | head
```

<details close>
  <summary> <h4>Image Results</h4> </summary>
    
![CVEDataLake](https://i.imgur.com/TOHj0Kz)
![CVEDataLake](https://i.imgur.com/PhcouoU)
  
  - **System dependencies**: (curl, unzip, python3, python3-pip) are installed
  - **Python libraries**: (boto3, botocore, python-dotenv, requests) are installed with required versions
  - **AWS CLI**: credentials and region are properly configured
  - **IAM identity**: is correctly authenticated via AWS CLI, confirming access to the AWS account
  - **S3 bucket**: exists and is accessible through the CLI
  - **SNS topic**: is successfully created, and its ARN matches the expected configuration

![CVEDataLake](https://i.imgur.com/wob1hNt)
  </details>

---
<br>

## Athena Queries

The `athena_queries.yaml` file contains sample queries designed to extract valuable insights from the CVE data lake. Each query focuses on a specific aspect of vulnerability management, such as critical vulnerabilities, vendor trends, or severity distributions.

**Key highlights**:
- **Top 100 Critical Windows Vulnerabilities**: Prioritize patching for high-risk Microsoft vulnerabilities
- **Top 20 Vendors with Most CVEs**: Monitor vendors with the most reported vulnerabilities
- **Top 20 Microsoft Products with Most Vulnerabilities**: Focus on high-risk Microsoft products
- **Top 20 Apple Critical CVEs**: Identify severe vulnerabilities in Apple products (CVSS > 9.0)
- **20 Latest Cisco High and Critical CVEs**: Track recent critical Cisco vulnerabilities
- **Top 10 CVEs with Most References**: Highlight vulnerabilities with significant community attention
- **Number of CVEs by Severity Level (CVSS v3)**: Categorize vulnerabilities by severity for better planning
- **List CVEs with SQL Injection**: Address risks related to SQL injection attacks

**Extending Queries**
- This file can be easily updated with new queries to meet evolving requirements. Simply modify `athena_queries.yaml`, then run the playbook to generate updated JSON report files, enabling continuous adaptability and insights.

**Now let's run the Sample Query Reports Playbook:**
```bash
ansible-playbook sample-reports.yaml -vv
```
  The `sample-reports.yaml` playbook will:
  - Define `Athena` queries to extract insights from the CVE data stored in the data lake
  - Execute the queries in `Athena` and capture the corresponding execution IDs
  - Download the resulting CSV files from the `S3` bucket using the captured execution IDs
  - Process, format the CSV files into JSON, and output to `query_results` directory using a Python script for improved readability and usability

> Note: *This playbook automates the process of running predefined queries, fetching their results, and preparing them in JSON format for use in dashboards, reports, or further analysis.*

**Confirm Successful Execution:**

```bash
aws s3 ls s3://cve-data-lake-thuynh/athena-results/ #Change "cve-data-lake-thuynh" to your bucket name
ll ~/CVEDataLake/query_results/
cat ~/CVEDataLake/query_results/Top_100_Critical_Windows_Vulnerabilities.json | head -40
```
<details close>
  <summary> <h4>Image Results</h4> </summary>
    
![CVEDataLake](https://i.imgur.com/idwIvVZ)
![CVEDataLake](https://i.imgur.com/fWI7OLO)

  - **Lambda Function**: Verify function name and ARN are correct; SNS Topic ARN is properly set as environment variable
  - **EventBridge Rule**: Confirm state is `ENABLED` and event pattern is set to trigger when an object is created in S3
  - **Cron Job**: a daily cron job exists to run the Python script (weather_data_aggregator.py) at the correct time (0 8 * * *)
  </details>

---
<br>

## Conclusion

CVEDataLake combines the power of AWS tools like S3, Glue, and Athena with Ansible automation to make vulnerability management seamless and efficient! Its modular design means you can easily add new queries, scale for larger datasets, or tweak it to meet specific needs. This makes it an incredible tool for SOC teams, security analysts, and even generating custom reports for audits, dashboards, or compliance.
