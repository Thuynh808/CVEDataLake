import csv
import json
import os
import argparse

def convert_csv_to_json(csv_file_path, query_name):
    try:
        # Ensure the input file exists
        if not os.path.exists(csv_file_path):
            raise FileNotFoundError(f"CSV file '{csv_file_path}' not found.")

        # Ensure the output directory exists
        output_dir = "/root/CVEDataLake/query_results"
        os.makedirs(output_dir, exist_ok=True)

        # Read CSV and convert to JSON
        with open(csv_file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            rows = list(csv_reader)

            if not rows:
                raise ValueError(f"No data found in the CSV file: {csv_file_path}")

            # Add metadata for query name
            output_data = {
                "query_name": query_name,
                "results": rows
            }

        # Determine the output file path
        output_file_name = f"{os.path.splitext(os.path.basename(csv_file_path))[0]}.json"
        output_file_path = os.path.join(output_dir, output_file_name)

        # Write JSON data to the output file
        with open(output_file_path, mode='w') as json_file:
            json.dump(output_data, json_file, indent=4)

        print(f"JSON output written to: {output_file_path}")

    except Exception as e:
        print(f"Error: {e}")
        exit(1)

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Convert CSV to JSON format and save to a fixed directory.")
    parser.add_argument("--file", required=True, help="Path to the input CSV file.")
    parser.add_argument("--query-name", required=True, help="Name of the Athena query.")
    args = parser.parse_args()

    # Convert CSV to JSON and save it to the output directory
    convert_csv_to_json(args.file, args.query_name)

if __name__ == "__main__":
    main()

