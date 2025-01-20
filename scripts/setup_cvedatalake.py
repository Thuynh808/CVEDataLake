import boto3
import json
import time
import requests
import gzip
from dotenv import load_dotenv
from datetime import datetime
import os

# Load environment variables from .env file
load_dotenv()

# AWS configurations
region = "us-east-1"
bucket_name = "cve-data-lake-thuynh"
glue_database_name = "glue_cve_data_lake"
glue_table_name = "cve_records"
athena_output_location = f"s3://{bucket_name}/athena-results/"

# NVD base URL for CVE data feeds
nvd_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"

# Create AWS clients
s3_client = boto3.client("s3", region_name=region)
glue_client = boto3.client("glue", region_name=region)
athena_client = boto3.client("athena", region_name=region)


def create_s3_bucket():
    """Create an S3 bucket for storing CVE data."""
    try:
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        print(f"S3 bucket '{bucket_name}' created successfully.")
    except Exception as e:
        print(f"Error creating S3 bucket: {e}")


def fetch_cve_data():
    """Fetch the entire CVE dataset from NVD."""
    try:
        print("Fetching NVD CVE dataset...")
        current_year = datetime.now().year
        years = list(range(2015, current_year + 1))
        all_cves = []

        for year in years:
            feed_url = f"{nvd_base_url}/nvdcve-1.1-{year}.json.gz"
            print(f"Downloading data for {year}: {feed_url}")

            response = requests.get(feed_url, stream=True)
            response.raise_for_status()

            print(f"Decompressing data for {year}...")
            with gzip.GzipFile(fileobj=response.raw) as gzipped_data:
                yearly_data = json.load(gzipped_data)
                all_cves.extend(yearly_data.get("CVE_Items", []))

            print(f"Successfully processed {len(yearly_data.get('CVE_Items', []))} CVEs for {year}.")

        print(f"Total CVEs fetched: {len(all_cves)}")
        return all_cves
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []


def flatten_cve_record(record):
    """Flatten a single CVE record."""
    try:
        # Extract top-level metadata
        cve_id = record["cve"]["CVE_data_meta"]["ID"]
        assigner = record["cve"]["CVE_data_meta"].get("ASSIGNER", "N/A")
        state = record["cve"]["CVE_data_meta"].get("STATE", "N/A")

        # Extract description
        description_data = record["cve"]["description"]["description_data"]
        description = description_data[0]["value"] if description_data else "N/A"

        # Extract CVSS scores
        cvss_v3 = record.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
        cvss_v3_vector = cvss_v3.get("vectorString", "N/A")
        cvss_v3_base_score = cvss_v3.get("baseScore", None)
        cvss_v3_base_severity = cvss_v3.get("baseSeverity", "N/A")
        cvss_v3_exploitability = record.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore", None)
        cvss_v3_impact = record.get("impact", {}).get("baseMetricV3", {}).get("impactScore", None)

        cvss_v2 = record.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
        cvss_v2_vector = cvss_v2.get("vectorString", "N/A")
        cvss_v2_base_score = cvss_v2.get("baseScore", None)

        # Extract CPE URIs
        cpe_uris = []
        vendors = []
        products = []
        for node in record.get("configurations", {}).get("nodes", []):
            for match in node.get("cpe_match", []):
                cpe_uris.append(match["cpe23Uri"])
                # Extract vendor and product from CPE string
                parts = match["cpe23Uri"].split(":")
                if len(parts) > 4:
                    vendors.append(parts[3])
                    products.append(parts[4])
        cpe_uris_str = ", ".join(cpe_uris)
        vendor_str = ", ".join(set(vendors))
        product_str = ", ".join(set(products))

        # Extract references
        references = record["cve"]["references"]["reference_data"]
        reference_urls = [ref.get("url", "N/A") for ref in references]
        references_str = ", ".join(reference_urls)

        # Extract credits (if available)
        credits = record.get("credits", [])
        credit_entries = [credit.get("value", "N/A") for credit in credits]
        credits_str = ", ".join(credit_entries)

        # Extract dates
        published_date = record.get("publishedDate", "N/A")
        last_modified_date = record.get("lastModifiedDate", "N/A")

        # Extract vulnerability type (if available)
        problemtype_data = record["cve"]["problemtype"]["problemtype_data"]
        vulnerability_types = [ptype.get("description", [{}])[0].get("value", "N/A") for ptype in problemtype_data if ptype.get("description")]
        vulnerability_type = ", ".join(vulnerability_types)

        return {
            "cve_id": cve_id,
            "assigner": assigner,
            "description": description,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v3_base_score": cvss_v3_base_score,
            "cvss_v3_base_severity": cvss_v3_base_severity,
            "cvss_v3_exploitability": cvss_v3_exploitability,
            "cvss_v3_impact": cvss_v3_impact,
            "cvss_v2_vector": cvss_v2_vector,
            "cvss_v2_base_score": cvss_v2_base_score,
            "cpe_uris": cpe_uris_str,
            "vendor": vendor_str,
            "product": product_str,
            "references": references_str,
            "credits": credits_str,
            "vulnerability_type": vulnerability_type,
            "state": state,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
        }
    except Exception as e:
        print(f"Error flattening record: {e}")
        return None


def preprocess_cve_data(data):
    """Flatten the entire CVE dataset."""
    print("Flattening CVE dataset...")
    flattened_data = []
    for record in data:
        flat_record = flatten_cve_record(record)
        if flat_record:
            flattened_data.append(flat_record)
    print(f"Flattened {len(flattened_data)} records successfully.")
    return flattened_data


def upload_data_to_s3(data, batch_size=10000):
    """Upload the flattened CVE data to S3 in newline-delimited JSON format."""
    try:
        print("Uploading CVE data to S3 in batches...")

        # Split the data into smaller chunks
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            batch_file_key = f"raw-data/cve_batch_{i // batch_size + 1}.json"

            # Convert batch to newline-delimited JSON
            line_delimited_json = "\n".join([json.dumps(record) for record in batch])

            # Upload each batch
            s3_client.put_object(
                Bucket=bucket_name,
                Key=batch_file_key,
                Body=line_delimited_json,
                ContentType="application/json"
            )
            print(f"Uploaded batch {i // batch_size + 1} to S3: {batch_file_key}")

        print("All CVE data batches uploaded successfully.")
    except Exception as e:
        print(f"Error uploading data to S3: {e}")


def create_glue_database():
    """Create a Glue database for the CVE data lake."""
    try:
        glue_client.create_database(
            DatabaseInput={
                "Name": glue_database_name,
                "Description": "Glue database for CVE vulnerability data lake.",
            }
        )
        print(f"Glue database '{glue_database_name}' created successfully.")
    except Exception as e:
        print(f"Error creating Glue database: {e}")


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
                        {"Name": "cve_id", "Type": "string"},  # Unique identifier for the CVE
                        {"Name": "assigner", "Type": "string"},  # Organization that assigned the CVE
                        {"Name": "description", "Type": "string"},  # Detailed description of the CVE
                        {"Name": "cvss_v3_vector", "Type": "string"},  # CVSS v3 vector string
                        {"Name": "cvss_v3_base_score", "Type": "float"},  # CVSS v3 base score
                        {"Name": "cvss_v3_base_severity", "Type": "string"},  # CVSS v3 severity level
                        {"Name": "cvss_v2_vector", "Type": "string"},  # CVSS v2 vector string
                        {"Name": "cvss_v2_base_score", "Type": "float"},  # CVSS v2 base score
                        {"Name": "cpe_uris", "Type": "string"},  # Affected product CPE URIs (comma-separated)
                        {"Name": "references", "Type": "string"},  # URLs to additional information (comma-separated)
                        {"Name": "published_date", "Type": "string"},  # Date the CVE was published
                        {"Name": "last_modified_date", "Type": "string"},  # Date the CVE was last modified
                        {"Name": "vendor", "Type": "string"},  # Vendor of the affected product
                        {"Name": "product", "Type": "string"},  # Affected product name
                        {"Name": "vulnerability_type", "Type": "string"},  # Type of vulnerability (e.g., buffer overflow)
                        {"Name": "exploitability_score", "Type": "float"},  # CVSS v3 exploitability score
                        {"Name": "impact_score", "Type": "float"},  # CVSS v3 impact score
                        {"Name": "state", "Type": "string"},  # Status of the CVE (e.g., PUBLISHED, REJECTED)
                        {"Name": "credits", "Type": "string"},  # Acknowledgments for the vulnerability (comma-separated)
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
    print("Setting up CVE data lake...")
    create_s3_bucket()
    time.sleep(5)  # Ensure bucket creation propagates
    create_glue_database()
    cve_data = fetch_cve_data()
    if cve_data:
        flattened_data = preprocess_cve_data(cve_data)
        upload_data_to_s3(flattened_data)
    create_glue_table()
    configure_athena_workgroup()
    print("CVE data lake setup complete.")


if __name__ == "__main__":
    main()
