#include <iostream>
#include <fstream>
#include <vector>
#include <tuple>
#include <sqlite3.h>
#include <iomanip>

std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, std::string>> get_cve_details(sqlite3* db, const std::string& search_term, const std::string& version) {
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, std::string>> cve_details;

    std::string query = R"(
        SELECT DISTINCT cve_range.vendor, cve_range.product, ? as version,
                        cve_severity.cve_number, cve_severity.severity, cve_severity.score, cve_severity.data_source
        FROM cve_range
        JOIN cve_severity ON cve_range.cve_number = cve_severity.cve_number
        LEFT JOIN cve_exploited ON cve_severity.cve_number = cve_exploited.cve_number
        WHERE cve_range.product = ? AND (
            (cve_range.versionStartIncluding IS NOT NULL AND cve_range.versionEndExcluding IS NOT NULL AND
             ? >= cve_range.versionStartIncluding AND ? < cve_range.versionEndExcluding)
        )
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, search_term.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, version.c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string vendor = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string version = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            std::string cve_number = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            std::string severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            std::string score = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            std::string data_source = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));

            cve_details.emplace_back(std::make_tuple(vendor, product, version, cve_number, severity, score, data_source));
        }

        sqlite3_finalize(stmt);
    }

    return cve_details;
}

std::string get_vendor(sqlite3* db, const std::string& product_name) {
    std::string vendor;

    std::string query = "SELECT DISTINCT vendor FROM cve_range WHERE product = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, product_name.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            vendor = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }

        sqlite3_finalize(stmt);
    }

    return vendor;
}
/*
void display_summary_table(const std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, std::string>>& data, const std::vector<std::string>& headers, const std::string& title) {
    if (!data.empty()) {
        std::cout << "\nTable for " << title << ":\n";
        for (const auto& header : headers) {
            std::cout << std::setw(20) << std::left << header;
        }
        std::cout << "\n";

        for (const auto& row : data) {
            for (const auto& field : row) {
                std::cout << std::setw(20) << std::left << field;
            }
            std::cout << "\n";
        }
    }
}
*/

template <typename... Args>
void display_summary_table(const std::vector<std::tuple<Args...>>& data, const std::vector<std::string>& headers, const std::string& title) {
    if (!data.empty()) {
        std::cout << "\nTable for " << title << ":\n";
        
        // Print headers
        for (const auto& header : headers) {
            std::cout << std::setw(20) << std::left << header;
        }
        std::cout << "\n";

        // Print rows
        for (const auto& row : data) {
            std::apply([](const auto&... fields) {
                ((std::cout << std::setw(20) << std::left << fields), ...);
                std::cout << "\n";
            }, row);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>\n";
        return 1;
    }

    const std::string input_file = argv[1];

    // Connect to the SQLite database
    sqlite3* db;
    if (sqlite3_open("/home/escan/aaaa/cvebintool/cve.db", &db) != SQLITE_OK) {
        std::cerr << "Error opening the database.\n";
        return 1;
    }

    // Read product names and versions from the input file
    std::ifstream file(input_file);
    if (!file.is_open()) {
        std::cerr << "Error opening input file.\n";
        sqlite3_close(db);
        return 1;
    }

    std::vector<std::tuple<std::string, std::string>> product_info;
    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> parts;
        size_t pos = 0;
        while ((pos = line.find(',')) != std::string::npos) {
            parts.push_back(line.substr(0, pos));
            line.erase(0, pos + 1);
        }
        if (!line.empty()) {
            parts.push_back(line);
        }
        if (parts.size() >= 2) {
            product_info.emplace_back(std::make_tuple(parts[0], parts[1]));
        }
    }

    if (product_info.empty()) {
        std::cerr << "No product names and versions found in the input file.\n";
        sqlite3_close(db);
        return 1;
    }

    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, std::string>> cve_found_details;
    std::vector<std::tuple<std::string, std::string, std::string>> cve_not_found_details;

    for (const auto& entry : product_info) {
        const std::string& product_name = std::get<0>(entry);
        const std::string& version = std::get<1>(entry);

        // Fetch details based on the product name and version, and remove duplicates
        auto cve_details = get_cve_details(db, product_name, version);

        if (!cve_details.empty()) {
            // Add details to the list for the identified vulnerabilities table
            cve_found_details.insert(cve_found_details.end(), cve_details.begin(), cve_details.end());
        } else {
            // Check if the product name exists in the database
            std::string vendor = get_vendor(db, product_name);
            if (!vendor.empty()) {
                // Product name matches but version doesn't
                cve_not_found_details.emplace_back(std::make_tuple(vendor, product_name, version));
            }
        }
    }
/*
    // Display tables
    if (!cve_found_details.empty()) {
        std::vector<std::string> headers = {"Vendor", "Product", "Version", "CVE Number", "Severity", "Score (CVSS Version)", "Source"};
        display_summary_table(cve_found_details, headers, "Products with Identified Vulnerabilities");
    }

    if (!cve_not_found_details.empty()) {
        std::vector<std::string> no_cve_headers = {"Vendor", "Product", "Version"};
        display_summary_table(cve_not_found_details, no_cve_headers, "Products with Version Mismatch");
    }
*/

         if (!cve_found_details.empty()) {
        std::vector<std::string> headers = {"Vendor", "Product", "Version", "CVE Number", "Severity", "Score (CVSS Version)", "Source"};
        display_summary_table(cve_found_details, headers, "Products with Identified Vulnerabilities");
    }

    if (!cve_not_found_details.empty()) {
        std::vector<std::string> no_cve_headers = {"Vendor", "Product", "Version"};
        display_summary_table(cve_not_found_details, no_cve_headers, "Products with Version Mismatch");
    }
    // Close the database connection
    sqlite3_close(db);

    return 0;
}

