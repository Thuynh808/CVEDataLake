import boto3
import json
import time
import requests
import gzip
from datetime import datetime
import os


# AWS configurations
region = os.getenv("AWS_REGION")
bucket_name = os.getenv("S3_BUCKET_NAME")
glue_database_name = os.getenv("GLUE_DATABASE_NAME")
glue_table_name = os.getenv("GLUE_TABLE_NAME")
athena_output_location = os.getenv("ATHENA_OUTPUT_LOCATION")

# NVD base URL for CVE data feeds
nvd_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"

# Create AWS clients
glue_client = boto3.client("glue", region_name=region)
athena_client = boto3.client("athena", region_name=region)


def create_glue_table():
    """Create a Glue table for the comprehensive CVE data."""
    try:
        # Check if the table already exists
        response = glue_client.get_table(
            DatabaseName=glue_database_name,
            Name=glue_table_name
        )
        print(f"Glue table '{glue_table_name}' already exists. Skipping creation.")
        return
    except glue_client.exceptions.EntityNotFoundException:
        pass

    try:
        glue_client.create_table(
            DatabaseName=glue_database_name,
            TableInput={
                "Name": glue_table_name,
                "StorageDescriptor": {
                    "Columns": [
                        {"Name": "cve_id", "Type": "string"},
                        {"Name": "assigner", "Type": "string"},
                        {"Name": "description", "Type": "string"},
                        {"Name": "cvss_v3_vector", "Type": "string"},
                        {"Name": "cvss_v3_base_score", "Type": "double"},
                        {"Name": "cvss_v3_base_severity", "Type": "string"},
                        {"Name": "cvss_v3_exploitability", "Type": "double"},
                        {"Name": "cvss_v3_impact", "Type": "double"},
                        {"Name": "cvss_v2_vector", "Type": "string"},
                        {"Name": "cvss_v2_base_score", "Type": "double"},
                        {"Name": "cpe_uris", "Type": "string"},
                        {"Name": "vendor", "Type": "string"},
                        {"Name": "product", "Type": "string"},
                        {"Name": "references", "Type": "string"},
                        {"Name": "credits", "Type": "string"},
                        {"Name": "vulnerability_type", "Type": "string"},
                        {"Name": "state", "Type": "string"},
                        {"Name": "published_date", "Type": "string"},
                        {"Name": "last_modified_date", "Type": "string"},
                    ],
                    "Location": f"s3://{bucket_name}/raw-data/",
                    "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                    "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    "SerdeInfo": {
                        "SerializationLibrary": "org.openx.data.jsonserde.JsonSerDe"
                    },
                },
                "TableType": "EXTERNAL_TABLE",
            },
        )
        print(f"Glue table '{glue_table_name}' created successfully.")
    except Exception as e:
        print(f"Error creating Glue table: {e}")


def configure_athena_workgroup():
    """Configure the Athena workgroup with a query result location."""
    try:
        workgroup_name = "CVEDataLakeWorkgroup"

        # Check if the workgroup exists
        try:
            response = athena_client.get_work_group(WorkGroup=workgroup_name)
            print(f"Athena workgroup '{workgroup_name}' already exists.")
        except athena_client.exceptions.InvalidRequestException:
            athena_client.create_work_group(
                Name=workgroup_name,
                Configuration={
                    "ResultConfiguration": {"OutputLocation": athena_output_location},
                },
                Description="Workgroup for CVE Data Lake queries",
            )
            print(f"Athena workgroup '{workgroup_name}' created successfully.")

        athena_client.update_work_group(
            WorkGroup=workgroup_name,
            ConfigurationUpdates={
                "EnforceWorkGroupConfiguration": True,
                "ResultConfigurationUpdates": {"OutputLocation": athena_output_location},
            },
        )
        print(f"Athena workgroup '{workgroup_name}' updated successfully.")
    except Exception as e:
        print(f"Error configuring Athena workgroup: {e}")


def main():
    create_glue_table()
    configure_athena_workgroup()


if __name__ == "__main__":
    main()
