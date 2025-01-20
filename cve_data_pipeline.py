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

# NVD base URL for CVE data feeds
nvd_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"

# Create AWS clients
s3_client = boto3.client("s3", region_name=region)


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


def main():
    print("Fetching CVE data...")
    cve_data = fetch_cve_data()
    if cve_data:
        flattened_data = preprocess_cve_data(cve_data)
        upload_data_to_s3(flattened_data)

if __name__ == "__main__":
    main()

