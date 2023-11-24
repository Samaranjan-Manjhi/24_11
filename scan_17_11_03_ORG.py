import sqlite3
from prettytable import PrettyTable
import argparse

def get_cve_details(cursor, search_term, version):
    query = ("""
        SELECT DISTINCT cve_range.vendor, cve_range.product, ? as version,
                        cve_severity.cve_number, cve_severity.severity, cve_severity.score, cve_severity.data_source
        FROM cve_range
        JOIN cve_severity ON cve_range.cve_number = cve_severity.cve_number
        LEFT JOIN cve_exploited ON cve_severity.cve_number = cve_exploited.cve_number
        WHERE cve_range.product = ? AND (
            (cve_range.versionStartIncluding IS NOT NULL AND cve_range.versionEndExcluding IS NOT NULL AND
             ? >= cve_range.versionStartIncluding AND ? < cve_range.versionEndExcluding)
        )
    """)
    cursor.execute(query, (version, search_term, version, version))
    cve_details = cursor.fetchall()
    return cve_details

def get_vendor(cursor, product_name):
    query = ("SELECT DISTINCT vendor FROM cve_range WHERE product = ?")
    cursor.execute(query, (product_name,))
    vendor = cursor.fetchone()
    return vendor[0] if vendor else None

def display_summary_table(data, headers, title):
    if data:
        table = PrettyTable(headers)
        table.align = 'l'
        for row in data:
            table.add_row(row)
        print(f"\nTable for {title}:")
        print(table)

def main(input_file):
    # Connect to the SQLite database
    db_path = "/home/escan/182_backup/aaaa/cvebintool/cve.db"
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    # Read product names and versions from the input file
    with open(input_file, 'r') as file:
        #product_info = [line.strip().split(',') for line in file]
        product_info = [line.strip().split('|') for line in file]

    if not product_info:
        print("No product names and versions found in the input file.")
        connection.close()
        return

    cve_found_details = []
    cve_not_found_details = []

    for entry in product_info:
        if len(entry) >= 2:
            product_name, version = entry[0], entry[1]

            # Fetch details based on the product name and version, and remove duplicates
            cve_details = get_cve_details(cursor, product_name, version)

            if cve_details:
                # Add details to the list for the identified vulnerabilities table
                cve_found_details.extend(cve_details)
            else:
                # Check if the product name exists in the database
                vendor = get_vendor(cursor, product_name)
                if vendor:
                    # Product name matches but version doesn't
                    cve_not_found_details.append((vendor, product_name, version))

    # Display tables
    if cve_found_details:
        headers = ["Vendor", "Product", "Version", "CVE Number", "Severity", "Score (CVSS Version)", "Source"]
        display_summary_table(cve_found_details, headers, "Products with Identified Vulnerabilities")

    if cve_not_found_details:
        no_cve_headers = ["Vendor", "Product", "Version"]
        display_summary_table(cve_not_found_details, no_cve_headers, "Products with Version Mismatch")

    # Close the database connection
    connection.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Scanner")
    parser.add_argument("input_file", help="Path to the input file containing product names and versions.")
    args = parser.parse_args()
    
    main(args.input_file)

