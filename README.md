![CVEDataLake](https://i.imgur.com/9qfpYjc.png)

## Project Overview
cvedatalake 

## Components

- **Rocky Linux VM**: Provides a RHEL-based and stable environment for Ansible and script execution
- **Ansible**: Automates the deployment of AWS infrastructure and project setup
- **Python:** Facilitates weather data fetching, aggregation, and automation through custom scripts:
  - Fetches weather data from the OpenWeather API
  - Uploads aggregated data to S3
  - Processes S3 events and sends notifications to SNS
- **AWS Services**:
  - **S3**: Stores object weather data
  - **SNS**: Manage notifications through topics and subscribers
  - **EventBridge**: Using event pattern rule to detect S3 object creation and trigger the Lambda function
  - **IAM**: Manages secure access to AWS services with fine-grained policies and roles
- **Email**: Delivers weather reports to end users via notifications sent through AWS SNS

## Versions

| Component        | Version  | Component     | Version |
|------------------|----------|---------------|---------|
| Rocky Linux      | 9.4      | Ansible       | 2.15    |
| AWS CLI          | Latest   | Community.aws | 9.0     |
| Python           | 3.9.21   | Amazon.aws    | 9.0     |
| Botocore         | 1.31.0   | Requests      | 2.28.2  |  
| Boto3            | 1.28.0   | python-dotenv | 1.0     |

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
git clone -b feature https://github.com/Thuynh808/cvedatalake
cd cvedatalake 
ansible-galaxy collection install -r requirements.yaml -vv
```
  Command Breakdown:
  - Navigates to home directory
  - Installs `Git` and `Ansible`
  - Clone repository
  - Navigates to project directory
  - Install required Ansible Collections

## Define Variables

**Update variables with proper values for files: `myvars.yaml` and `.env`**
```bash
vim myvars.yaml
```
```bash
accesskeyid: "<your-access-key-id>"
secretaccesskey: "<your-secret-access-key>"
defaultregion: "us-east-1"
emailendpoint: "<your-email>"
bucketname: "<your-bucket-name>"
```
```bash
vim .env
```
```bash
OPENWEATHER_API_KEY=<your-api-key>
AWS_BUCKET_NAME=<your-bucket-name>
AWS_REGION=us-east-1
```
**Set permissions to secure file**
```bash
chmod 0600 .env myvars.yaml 
```
> Note: Keep  sensitive files local. Add to `.gitignore` if uploading to GitHub
<br>  

## Deployment and Testing

**Run Playbook:**
```bash
ansible-playbook setup_infra.yaml -vv
ansible-playbook gluetable_athena.yaml -vv
```
```bash
ansible-playbook fetch_process_cve.yaml -vv
```
  The `weather_env_s3_sns.yaml` playbook will:
  - Install and upgrade system packages
  - Install `pip` modules with required versions
  - Download, unzip and install `AWS CLI`
  - Configure `AWS CLI`
  - Create S3 bucket
  - Create SNS topic to send notifications to email subscriber
  - Append SNS Amazon Resource Name (ARN) to `myvars.yaml` file

**Confirm Successful Execution:**
```bash
rpm -qa curl unzip python3 python3-pip
pip list | egrep "boto3|botocore|python-dotenv|requests" 
aws configure list
aws sts get-caller-identity
aws s3 ls
aws sns list-topics
```
<details close>
  <summary> <h4>Image Results</h4> </summary>
    
![Weather-Dashboard-Automation](https://i.imgur.com/P7ASLna.png)
  
  - **System dependencies**: (curl, unzip, python3, python3-pip) are installed
  - **Python libraries**: (boto3, botocore, python-dotenv, requests) are installed with required versions
  - **AWS CLI**: credentials and region are properly configured
  - **IAM identity**: is correctly authenticated via AWS CLI, confirming access to the AWS account
  - **S3 bucket**: exists and is accessible through the CLI
  - **SNS topic**: is successfully created, and its ARN matches the expected configuration
  </details>

---

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
