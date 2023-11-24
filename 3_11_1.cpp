#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <zlib.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

using namespace std;

using json = nlohmann::json;
namespace fs = std::filesystem;

class CVEDataProcessor {
        public:
                CVEDataProcessor(const std::string& database_file = "/home/escan/aaaa/cvebintool/cve_cpp.db")
                        : database_file_(database_file), cachedir_("/home/escan/181023/data_source") {
                                connection_ = nullptr;
                        }

                void refresh() {
                        std::cout<<"This is refresh function"<<endl;
                        initDatabase();
                        process_All_Cache_Dirs();
                        dbOpen();
                        updateExploits();
                        populateExploitDb();
                        insertExploitToDb();
                        insertCVEData();
                        entryExists();   
                        insertCVESeverity();
                        insertCVERange();
                        insertCVERangeNode();
                        insertCVERangeInfo();
                }

                void processAllJsonGzFiles(const std::vector<std::string>& cache_dirs) {
                        for (const auto& cache_dir : cache_dirs) {
                                processCacheDir(cache_dir);
                        }
                        updateExploits();
                }

                void initDatabase() {
                        std::cout<<"This is initDatabase function"<<endl;
                        dbOpen();
                        char* errMsg = 0;

                        const char* cveDataCreate = R"(
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
            );
        )";

                        const char* versionRangeCreate = R"(
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
            );
        )";

                        const char* exploitTableCreate = R"(
            CREATE TABLE IF NOT EXISTS cve_exploited (
                cve_number TEXT,
                product TEXT,
                description TEXT,
                PRIMARY KEY(cve_number)
            );
        )";

                        const char* indexRange = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)";

                        sqlite3_exec(connection_, cveDataCreate, 0, 0, &errMsg);
                        sqlite3_exec(connection_, versionRangeCreate, 0, 0, &errMsg);
                        sqlite3_exec(connection_, exploitTableCreate, 0, 0, &errMsg);
                        sqlite3_exec(connection_, indexRange, 0, 0, &errMsg);

                        sqlite3_close(connection_);
                }




        private:
                sqlite3* connection_;
                std::string database_file_;
                std::string cachedir_;

                void process_All_Cache_Dirs() {
                        std::cout<<"This is process_All_Cache_Dirs function"<<endl;
                        std::vector<std::string> cache_dirs = {
                                "/home/escan/181023/data_source/nvd",
                        };

                        for (const auto& cache_dir : cache_dirs) {
                                processCacheDir(cache_dir);
                        }
                }

                void processCacheDir(const std::string& cache_dir) {
                        std::cout<<"This is processCacheDir function"<<endl;
                        if (!fs::exists(cache_dir)) {
                                std::cout << "Cache directory does not exist: " << cache_dir << std::endl;
                                return;
                        }

                        for (const auto& entry : fs::directory_iterator(cache_dir)) {
                                if (fs::is_regular_file(entry) && entry.path().extension() == ".json.gz") {
                                        std::string filepath = entry.path().string();
                                        std::ifstream file(filepath, std::ios::binary);

                                        if (!file) {
                                                std::cout << "Error opening gzipped file: " << filepath << std::endl;
                                                continue;
                                        }

                                        z_stream gzFile;
                                        gzFile.zalloc = Z_NULL;
                                        gzFile.zfree = Z_NULL;
                                        gzFile.opaque = Z_NULL;
                                        gzFile.avail_in = 0;
                                        gzFile.next_in = Z_NULL;
                                        if (inflateInit2(&gzFile, 15 + 32) != Z_OK) {
                                                std::cout << "Error initializing zlib for: " << filepath << std::endl;
                                                continue;
                                        }

                                        std::ostringstream oss;
                                        char inbuf[1024];
                                        char outbuf[1024];
                                        do {
                                                file.read(inbuf, sizeof(inbuf));
                                                gzFile.avail_in = file.gcount();
                                                gzFile.next_in = reinterpret_cast<Bytef*>(inbuf);

                                                do {
                                                        gzFile.avail_out = sizeof(outbuf);
                                                        gzFile.next_out = reinterpret_cast<Bytef*>(outbuf);
                                                        if (inflate(&gzFile, Z_NO_FLUSH) < 0) {
                                                                std::cout << "Error inflating data for: " << filepath << std::endl;
                                                                inflateEnd(&gzFile);
                                                                break;
                                                        }
                                                        oss.write(outbuf, sizeof(outbuf) - gzFile.avail_out);
                                                } while (gzFile.avail_out == 0);
                                        } while (file);

                                        inflateEnd(&gzFile);

                                        std::string content = oss.str();
                                        json json_data = json::parse(content);

                                        insertCVEData(json_data);
                                }
                        }
                }

                /*
                   void initDatabase() {
                   dbOpen();
                   char* errMsg = 0;

                   const char* cveDataCreate = R"(
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
                   );
                   )";

                   const char* versionRangeCreate = R"(
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
                   );
                   )";

                   const char* exploitTableCreate = R"(
                   CREATE TABLE IF NOT EXISTS cve_exploited (
                   cve_number TEXT,
                   product TEXT,
                   description TEXT,
                   PRIMARY KEY(cve_number)
                   );
                   )";

                   const char* indexRange = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)";

                   sqlite3_exec(connection_, cveDataCreate, 0, 0, &errMsg);
                   sqlite3_exec(connection_, versionRangeCreate, 0, 0, &errMsg);
                   sqlite3_exec(connection_, exploitTableCreate, 0, 0, &errMsg);
                   sqlite3_exec(connection_, indexRange, 0, 0, &errMsg);

                   sqlite3_close(connection_);
                   }
                 */
                void dbOpen() {
                        if (!connection_) {
                                int rc = sqlite3_open(database_file_.c_str(), &connection_);
                                if (rc) {
                                        std::cerr << "Cannot open database: " << sqlite3_errmsg(connection_) << std::endl;
                                        std::exit(1);
                                }        
                        }
                }

                void updateExploits() {
                        std::cout<<"This is updateExploits function"<<endl;
                        std::string url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

                        CURL* curl = curl_easy_init();
                        if (!curl) {
                                std::cerr << "Failed to initialize CURL." << std::endl;
                                return;
                        }

                        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

                        // Store the received data in a string
                        std::string receivedData;
                        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &receivedData);

                        CURLcode res = curl_easy_perform(curl);
                        if (res != CURLE_OK) {
                                std::cerr << "CURL failed with error: " << curl_easy_strerror(res) << std::endl;
                                curl_easy_cleanup(curl);
                                return;
                        }

                        curl_easy_cleanup(curl);

                        // Parse the received JSON data
                        json jsonData = json::parse(receivedData);
                        if (jsonData.contains("vulnerabilities")) {
                                const json& cves = jsonData["vulnerabilities"];
                                std::vector<std::tuple<std::string, std::string, std::string>> exploitList;

                                for (const auto& cve : cves) {
                                        std::string cveID = cve["cveID"];
                                        std::string product = cve["product"];
                                        std::string shortDescription = cve["shortDescription"];
                                        exploitList.push_back(std::make_tuple(cveID, product, shortDescription));
                                }

                                populateExploitDb(exploitList);
                        }
                }

                void populateExploitDb(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
                        std::cout<<"This is populateExploitDb function"<<endl;
                        dbOpen();

                        for (const auto& exploit : exploitList) {
                                insertExploitToDb(std::get<0>(exploit), std::get<1>(exploit), std::get<2>(exploit));
                        }

                        sqlite3_close(connection_);
                }

                void insertExploitToDb(const std::string& cveNumber, const std::string& product, const std::string& description) {
                        std::cout<<"This is insertExploitToDb function"<<endl;
                        const char* insertQuery = R"(
            INSERT OR REPLACE INTO cve_exploited (
                cve_number,
                product,
                description
            )
            VALUES (?, ?, ?)
        )";

                        sqlite3_stmt* stmt;
                        sqlite3_prepare_v2(connection_, insertQuery, -1, &stmt, nullptr);
                        sqlite3_bind_text(stmt, 1, cveNumber.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 2, product.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                }

                static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
                        size_t totalSize = size * nmemb;
                        output->append(reinterpret_cast<char*>(contents), totalSize);
                        return totalSize;
                }

                std::tuple<std::string, std::string, int, double, std::string, std::string, std::string> extractSeverityInfo(const json& cve_item) {
                        std::cout<<"This is tuple function"<<endl;
                        std::string severity = "Unknown";
                        std::string description = "No description available";
                        int score = 0;
                        double cvss_version = 0.0;
                        std::string cvss_vector = "Unknown";
                        std::string data_source = "NVD";
                        std::string last_modified = "Unknown";

                        if (cve_item.contains("cve")) {
                                const json& cve = cve_item["cve"];
                                if (cve.contains("description") && cve["description"].contains("description_data")) {
                                        const json& descriptionData = cve["description"]["description_data"];
                                        if (!descriptionData.empty()) {
                                                description = descriptionData[0].value("value", "No description available");
                                        }
                                }

                                if (cve_item.contains("impact")) {
                                        const json& impact = cve_item["impact"];

                                        if (impact.contains("baseMetricV3")) {
                                                const json& impactV3 = impact["baseMetricV3"];
                                                severity = impactV3.value("cvssV3", json()).value("baseSeverity", "Unknown");
                                                score = impactV3.value("cvssV3", json()).value("baseScore", 0);
                                                cvss_version = impactV3.value("cvssV3", json()).value("version", 0.0);
                                                cvss_vector = impactV3.value("cvssV3", json()).value("vectorString", "Unknown");
                                                last_modified = cve_item.value("lastModifiedDate", "Unknown");
                                        } 
                                        else if (impact.contains("baseMetricV2")) {
                                                const json& impactV2 = impact["baseMetricV2"];
                                                severity = impactV2.value("severity", "Unknown");
                                                score = impactV2.value("cvssV2", json()).value("baseScore", 0);
                                                cvss_version = impactV2.value("cvssV2", json()).value("version", 0.0);
                                                cvss_vector = impactV2.value("cvssV2", json()).value("vectorString", "Unknown");
                                                last_modified = cve_item.value("lastModifiedDate", "Unknown");
                                        }
                                }
                        }

                        return std::make_tuple(severity, description, score, cvss_version, cvss_vector, data_source, last_modified);
                }

                void insertCVEData(const json& json_data) {
                        std::cout<<"This is insertCVEData function"<<endl;
                        dbOpen();

                        for (const auto& cve_item : json_data["CVE_Items"]) {
                                std::string cve_number = cve_item["cve"]["CVE_data_meta"]["ID"].get<std::string>();

                                if (!entryExists(cve_number)) {
                                        auto [severity, description, score, cvss_version, cvss_vector, data_source, last_modified] = extractSeverityInfo(cve_item);
                                        insertCVESeverity(cve_number, severity, description, score, cvss_version, cvss_vector, data_source, last_modified);
                                        insertCVERange(cve_number, cve_item["configurations"]);
                                }
                        }
                }

                bool entryExists(const std::string& cve_number) {
                        std::cout<<"This is entryExists function"<<endl;
                        dbOpen();
                        std::string query = "SELECT 1 FROM cve_severity WHERE cve_number = ?";
                        sqlite3_stmt* stmt;
                        sqlite3_prepare_v2(connection_, query.c_str(), -1, &stmt, nullptr);
                        sqlite3_bind_text(stmt, 1, cve_number.c_str(), -1, SQLITE_STATIC);
                        int result = sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                        return result == SQLITE_ROW;
                }

                void insertCVESeverity(const std::string& cve_number, const std::string& severity, 
                                const std::string& description, int score, double cvss_version, 
                                const std::string& cvss_vector, const std::string& data_source, 
                                const std::string& last_modified) {
                        std::cout<<"This is insertCVESeverity function"<<endl;
                        const char* insert_query = R"(
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
        )";

                        sqlite3_stmt* stmt;
                        sqlite3_prepare_v2(connection_, insert_query, -1, &stmt, nullptr);
                        sqlite3_bind_text(stmt, 1, cve_number.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 2, severity.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_int(stmt, 4, score);
                        sqlite3_bind_double(stmt, 5, cvss_version);
                        sqlite3_bind_text(stmt, 6, cvss_vector.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 7, data_source.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 8, last_modified.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                }

                void insertCVERange(const std::string& cve_number, const json& configurations) {
                        std::cout<<"This is insertCVERange function"<<endl;
                        if (configurations.contains("nodes")) {
                                for (const auto& node : configurations["nodes"]) {
                                        insertCVERangeNode(cve_number, node);

                                        if (node.contains("children")) {
                                                for (const auto& child : node["children"]) {
                                                        insertCVERangeNode(cve_number, child);
                                                }
                                        }
                                }
                        }
                }

                void insertCVERangeNode(const std::string& cve_number, const json& node) {
                        std::cout<<"This is insertCVERangeNode function"<<endl;
                        if (node.contains("cpe_match")) {
                                for (const auto& cpe_match : node["cpe_match"]) {
                                        std::string cpe23Uri = cpe_match["cpe23Uri"].get<std::string>();
                                        std::vector<std::string> cpe_split;
                                        std::istringstream iss(cpe23Uri);
                                        std::string token;

                                        while (std::getline(iss, token, ':')) {
                                                cpe_split.push_back(token);
                                        }

                                        std::string vendor, product, version;
                                        if (cpe_split.size() >= 6) {
                                                vendor = cpe_split[3];
                                                product = cpe_split[4];
                                                version = cpe_split[5];
                                        }

                                        std::string versionStartIncluding = cpe_match["versionStartIncluding"].get<std::string>();
                                        std::string versionStartExcluding = cpe_match["versionStartExcluding"].get<std::string>();
                                        std::string versionEndIncluding = cpe_match["versionEndIncluding"].get<std::string>();
                                        std::string versionEndExcluding = cpe_match["versionEndExcluding"].get<std::string>();

                                        insertCVERangeInfo(cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding);
                                }
                        }
                }

                void insertCVERangeInfo(const std::string& cve_number, const std::string& vendor, const std::string& product,
                                const std::string& version, const std::string& versionStartIncluding,
                                const std::string& versionStartExcluding, const std::string& versionEndIncluding,
                                const std::string& versionEndExcluding) {
                        std::cout<<"This is insertCVERangeInfo function"<<endl;
                        const char* insert_query = R"(
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
        )";

                        sqlite3_stmt* stmt;
                        sqlite3_prepare_v2(connection_, insert_query, -1, &stmt, nullptr);
                        sqlite3_bind_text(stmt, 1, cve_number.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 2, vendor.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 3, product.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 4, version.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 5, versionStartIncluding.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 6, versionStartExcluding.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 7, versionEndIncluding.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 8, versionEndExcluding.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                }
};

int main() {
        CVEDataProcessor cveDataProcessor;

        // Initialize the database tables
        cveDataProcessor.initDatabase();

        std::vector<std::string> cacheDirs = {
                "/home/escan/181023/data_source/nvd",
                // Add more directories if needed
        };

        cveDataProcessor.processAllJsonGzFiles(cacheDirs);

        // Process data from all cache directories and update exploits
        cveDataProcessor.refresh();

        return 0;
}

