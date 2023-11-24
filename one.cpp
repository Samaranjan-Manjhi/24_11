#include <iostream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <zlib.h>

using namespace std;
using json = nlohmann::json;

string getValueAsString(const json& value) {
    if (value.is_string()) {
        return value.get<string>();
    } else if (value.is_number()) {
        return to_string(value.get<double>());
    } else {
        return "";
    }
}

bool decompressGzipFile(const string& filePath, stringstream& decompressedData) {
    gzFile file = gzopen(filePath.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open gzipped file." << endl;
        return false;
    }

    char buffer[4096];
    int bytesRead = 0;

    while ((bytesRead = gzread(file, buffer, sizeof(buffer))) > 0) {
        decompressedData.write(buffer, bytesRead);
    }

    gzclose(file);
    return true;
}

int main() {
    const string gzippedFilePath = "/tmp/nvdcve-1.1-2002.json.gz";

    // Decompress the gzipped file
    stringstream decompressedData;
    if (!decompressGzipFile(gzippedFilePath, decompressedData)) {
        return 1;
    }

    // Parse the JSON data
    json jsonData;
    try {
        jsonData = json::parse(decompressedData);
    } catch (const exception& e) {
        cerr << "Failed to parse JSON data: " << e.what() << endl;
        return 1;
    }

    // Check if the required fields are present
    if (!jsonData.is_object() || !jsonData.contains("CVE_Items")) {
        cerr << "Invalid JSON format. Missing 'CVE_Items' field." << endl;
        return 1;
    }

    const json& cveItems = jsonData["CVE_Items"];
    if (!cveItems.is_array()) {
        cerr << "Invalid JSON format. 'CVE_Items' is not an array." << endl;
        return 1;
    }

    // Iterate over CVE items
    for (const auto& cveItem : cveItems) {
    	const json& cve = cveItem["cve"];
        const json& cve_data_meta = cve["CVE_data_meta"];
        const json& id = cve_data_meta["ID"];
        const json& severity = cveItem["impact"]["baseMetricV2"]["severity"];
        const json& description = cve["description"]["description_data"][0]["value"];
        const json& score = cveItem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"];
        const json& version = cveItem["impact"]["baseMetricV2"]["cvssV2"]["version"];
        const json& vectorString = cveItem["impact"]["baseMetricV2"]["cvssV2"]["vectorString"];
        const json& lastModifiedDate = cveItem["lastModifiedDate"];

        // Print the extracted data
        cout << "ID: " << getValueAsString(id) << endl;
        cout << "Severity: " << getValueAsString(severity) << endl;
        cout << "Description: " << getValueAsString(description) << endl;
        cout << "Score: " << getValueAsString(score) << endl;
        cout << "Version: " << getValueAsString(version) << endl;
        cout << "Vector String: " << getValueAsString(vectorString) << endl;
        cout << "Last Modified Date: " << getValueAsString(lastModifiedDate) << endl;

        // Print a separator between entries
        cout << "---------------------" << endl;
        // ... (rest of the code remains unchanged)
    }

    return 0;
}
