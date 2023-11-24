import os
import sqlite3
import gzip
import json
from pathlib import Path
import aiohttp
import asyncio
import requests

class CVEDataProcessor:
    def __init__(self, database_file="/opt/MicroWorld/scan_vul/database/cve_py.db"):
        self.connection = None
        self.database_file = database_file
        self.cachedir = "/opt/MicroWorld/scan_vul/data_source"

    async def refresh(self):
        self.init_database()
        await self.process_all_cache_dirs()
        self.update_exploits()  # Call to update the exploits data

    async def process_all_cache_dirs(self):
        # List of cache directories
        cache_dirs = [
                "/opt/MicroWorld/scan_vul/data_source/nvd",
                #"/home/escan/181023/data_source/epss",
                ]

        for cache_dir in cache_dirs:
            await self.process_cache_dir(cache_dir)

    async def process_cache_dir(self, cache_dir):
        if not os.path.exists(cache_dir):
            print(f"Cache directory does not exist: {cache_dir}")
            return

        for file in Path(cache_dir).glob("*.json.gz"):
            with gzip.open(file, "rb") as gz_file:
                try:
                    json_data = json.load(gz_file)
                except json.decoder.JSONDecodeError:
                    print(f"Error loading JSON data from {file}. Skipping...")
                    continue
                except gzip.BadGzipFile:
                    print(f"Error reading a non-gzip file: {file}. Skipping...")
                    continue
                self.insert_cve_data(json_data)

    def init_database(self):
        if not os.path.exists(self.database_file):
            print(f"Database file does not exist: {self.database_file}")
            print("Creating a new database...")
            self.create_database()

        self.db_open()
        cursor = self.connection.cursor()

        cve_data_create = """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER,
            cvss_vector TEXT,
            data_source TEXT,
            last_modified TIMESTAMP,
            PRIMARY KEY(cve_number, data_source)
        )
        """
        version_range_create = """
        CREATE TABLE IF NOT EXISTS cve_range (
            cve_number TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            versionStartIncluding TEXT,
            versionStartExcluding TEXT,
            versionEndIncluding TEXT,
            versionEndExcluding TEXT,
            data_source TEXT,
            FOREIGN KEY(cve_number, data_source) REFERENCES cve_severity(cve_number, data_source)
        )
        """
        exploit_table_create = """
        CREATE TABLE IF NOT EXISTS cve_exploited (
            cve_number TEXT,
            product TEXT,
            description TEXT,
            PRIMARY KEY(cve_number)
        )
        """

        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(exploit_table_create)
        cursor.execute(index_range)

        self.connection.commit()

    def create_database(self):
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(self.database_file), exist_ok=True)

        # Create the database file and call init_database to create tables
        self.connection = sqlite3.connect(self.database_file)
        self.init_database()

    def db_open(self):
        if self.connection is None:
            self.connection = sqlite3.connect(self.database_file)

    def update_exploits(self):
        """Get the latest list of vulnerabilities from cisa.gov and add them to the exploits database table."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=300)
        data = r.json()
        cves = data["vulnerabilities"]
        exploit_list = []
        for cve in cves:
            exploit_list.append((cve["cveID"], cve["product"], cve["shortDescription"]))
        self.populate_exploit_db(exploit_list)

    def populate_exploit_db(self, exploit_list):
        self.db_open()
        cursor = self.connection.cursor()

        for exploit in exploit_list:
            cursor.execute(self.insert_exploit, exploit)

        self.connection.commit()

    # SQL query for inserting exploits
    insert_exploit = """
        INSERT OR REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
        )
        VALUES (?, ?, ?)
    """

    def extract_severity_info(self, cve_item):
        #cve_number = cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown")
        description_data = cve_item.get("cve", {}).get("description", {}).get("description_data", [])
        description = description_data[0]["value"] if description_data else "No description available"
    
        # Check for V3 first
        impact_v3 = cve_item.get("impact", {}).get("baseMetricV3", {})
        if impact_v3:
            severity = impact_v3.get("cvssV3", {}).get("baseSeverity", "Unknown")
            score = impact_v3.get("cvssV3", {}).get("baseScore", 0)
            cvss_version = impact_v3.get("cvssV3", {}).get("version", 0.0)
            cvss_vector = impact_v3.get("cvssV3", {}).get("vectorString", "Unknown")
            data_source = "NVD"  # Default value
            last_modified = cve_item.get("lastModifiedDate", "Unknown")
        else:
            # If V3 is not present, check for V2
            impact_v2 = cve_item.get("impact", {}).get("baseMetricV2", {})
            if impact_v2:
                severity = impact_v2.get("severity", "Unknown")
                score = impact_v2.get("cvssV2", {}).get("baseScore", 0)
                cvss_version = impact_v2.get("cvssV2", {}).get("version", 0.0)
                cvss_vector = impact_v2.get("cvssV2", {}).get("vectorString", "Unknown")
                data_source = "NVD"  # Default value
                last_modified = cve_item.get("lastModifiedDate", "Unknown")
            else:
                # Neither V3 nor V2 data is present
                severity = "Unknown"
                score = 0
                cvss_version = 0.0
                cvss_vector = "Unknown"
                data_source = "NVD"  # Default value
                last_modified = cve_item.get("lastModifiedDate", "Unknown")
    
        return severity, description, score, cvss_version, cvss_vector, data_source, last_modified

    

    def insert_cve_data(self, json_data):
        self.db_open()
        cursor = self.connection.cursor()

        for cve_item in json_data.get("CVE_Items", []):
            cve_number = cve_item["cve"]["CVE_data_meta"]["ID"]

            # Check if the CVE entry already exists in the database
            cursor.execute("SELECT 1 FROM cve_severity WHERE cve_number = ?", (cve_number,))
            existing_entry = cursor.fetchone()

            if not existing_entry:
                severity, description, score, cvss_version, cvss_vector, data_source, last_modified = self.extract_severity_info(cve_item)
                self.insert_cve_severity(cursor, cve_number, severity, description, score, cvss_version, cvss_vector, data_source, last_modified)
                self.insert_cve_range(cursor, cve_number, cve_item.get("configurations", {}))

        self.connection.commit()

    def insert_cve_severity(self, cursor, cve_number, severity, description, score, cvss_version, cvss_vector, data_source, last_modified):
        insert_query = """
        INSERT OR REPLACE INTO cve_severity (
            cve_number,
            severity,
            description,
            score,
            cvss_version,
            cvss_vector,
            data_source, 
            last_modified
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (cve_number, severity, description, score, cvss_version, cvss_vector, data_source, last_modified))

    def insert_cve_range(self, cursor, cve_number, configurations):
        if "nodes" in configurations:
            for node in configurations["nodes"]:
                self.insert_cve_range_node(cursor, cve_number, node)
                if "children" in node:
                    for child in node["children"]:
                        self.insert_cve_range_node(cursor, cve_number, child)

    def insert_cve_range_node(self, cursor, cve_number, node):
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                cpe_split = cpe_match["cpe23Uri"].split(":")
                vendor, product, version = cpe_split[3], cpe_split[4], cpe_split[5]
                version_info = {
                        "versionStartIncluding": cpe_match.get("versionStartIncluding", ""),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding", ""),
                        "versionEndIncluding": cpe_match.get("versionEndIncluding", ""),
                        "versionEndExcluding": cpe_match.get("versionEndExcluding", ""),
                        }
                self.insert_cve_range_info(cursor, cve_number, vendor, product, version, **version_info)

    def insert_cve_range_info(self, cursor, cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding):
        insert_query = """
        INSERT OR REPLACE INTO cve_range (
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding))

if __name__ == "__main__":
    cve_data_processor = CVEDataProcessor()

    # Initialize the database tables
    cve_data_processor.init_database()

    # Process data from all cache directories and update exploits
    asyncio.run(cve_data_processor.refresh())

