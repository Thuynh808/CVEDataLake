import csv
import argparse

def format_csv_to_table(csv_file, query_name):
    table = f"## {query_name}\n\n"
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        rows = list(reader)

        # Extract headers and data
        headers = rows[0]
        data = rows[1:]

        # Format headers
        table += "| " + " | ".join(headers) + " |\n"
        table += "| " + " | ".join(["---"] * len(headers)) + " |\n"

        # Format data rows
        for row in data:
            table += "| " + " | ".join(row) + " |\n"

    return table

def main():
    parser = argparse.ArgumentParser(description="Format CVE CSV to Markdown Table")
    parser.add_argument("--file", required=True, help="Path to the CSV file")
    parser.add_argument("--query-name", required=True, help="Name of the query")
    args = parser.parse_args()

    table = format_csv_to_table(args.file, args.query_name)
    print(table)

if __name__ == "__main__":
    main()

