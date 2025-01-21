import boto3
from botocore.exceptions import ClientError

# AWS configurations
region = "us-east-1"
bucket_name = "cve-data-lake-thuynh"
glue_database_name = "glue_cve_data_lake"
glue_table_name = "cve_records"
athena_workgroup_name = "CVEDataLakeWorkgroup"

# Create AWS clients
s3_client = boto3.client("s3", region_name=region)
glue_client = boto3.client("glue", region_name=region)
athena_client = boto3.client("athena", region_name=region)
sns_client = boto3.client("sns", region_name=region)


def delete_s3_bucket(bucket_name):
    """Delete the S3 bucket and its contents."""
    try:
        print(f"Deleting all objects in bucket '{bucket_name}'...")
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects})
                print(f"Deleted {len(objects)} objects.")
        print(f"Deleting bucket '{bucket_name}'...")
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"S3 bucket '{bucket_name}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting S3 bucket '{bucket_name}': {e}")


def delete_glue_table(database_name, table_name):
    """Delete the Glue table."""
    try:
        print(f"Deleting Glue table '{table_name}' in database '{database_name}'...")
        glue_client.delete_table(DatabaseName=database_name, Name=table_name)
        print(f"Glue table '{table_name}' deleted successfully.")
    except glue_client.exceptions.EntityNotFoundException:
        print(f"Glue table '{table_name}' does not exist.")
    except ClientError as e:
        print(f"Error deleting Glue table '{table_name}': {e}")


def delete_glue_database(database_name):
    """Delete the Glue database."""
    try:
        print(f"Deleting Glue database '{database_name}'...")
        glue_client.delete_database(Name=database_name)
        print(f"Glue database '{database_name}' deleted successfully.")
    except glue_client.exceptions.EntityNotFoundException:
        print(f"Glue database '{database_name}' does not exist.")
    except ClientError as e:
        print(f"Error deleting Glue database '{database_name}': {e}")


def delete_athena_workgroup(workgroup_name):
    """Delete the Athena workgroup."""
    try:
        print(f"Deleting Athena workgroup '{workgroup_name}'...")
        athena_client.delete_work_group(WorkGroup=workgroup_name, RecursiveDeleteOption=True)
        print(f"Athena workgroup '{workgroup_name}' deleted successfully.")
    except athena_client.exceptions.InvalidRequestException:
        print(f"Athena workgroup '{workgroup_name}' does not exist.")
    except ClientError as e:
        print(f"Error deleting Athena workgroup '{workgroup_name}': {e}")


def main():
    print("Starting cleanup process...")
    delete_s3_bucket(bucket_name)
    delete_glue_table(glue_database_name, glue_table_name)
    delete_glue_database(glue_database_name)
    delete_athena_workgroup(athena_workgroup_name)
    print("Cleanup process completed.")


if __name__ == "__main__":
    main()

