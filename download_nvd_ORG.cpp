#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <vector>
#include <curl/curl.h>

// File download callback function
static size_t WriteToFileCallback(void* contents, size_t size, size_t nmemb, void* userData) {
    std::ofstream* file = static_cast<std::ofstream*>(userData);
    file->write(static_cast<const char*>(contents), size * nmemb);
    return size * nmemb;
}

class NVD_Source {
public:
    NVD_Source() {
        cacheDirPath = "/home/escan/181023/data_source";
        cacheDirName = "nvd";
        cacheDir = cacheDirPath + "/" + cacheDirName;
        session = nullptr;
    }

    ~NVD_Source() {
        if (session) {
            curl_easy_cleanup(session);
        }
    }

    void downloadCVEData() {
        if (!session) {
            session = curl_easy_init();
            curl_easy_setopt(session, CURLOPT_TCP_KEEPALIVE, 1L);
        }

        // Create the cache directory if it doesn't exist
        std::string cmd = "mkdir -p " + cacheDir;
        system(cmd.c_str());

        int currentYear = getCurrentYear();
        std::string base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-";

        // Create a list to store downloaded file paths
        std::vector<std::string> downloadedFiles;

        for (int year = 2002; year <= currentYear; ++year) {
            std::string urlToCVEData = base_url + std::to_string(year) + ".json.gz";
            std::string filename = urlToCVEData.substr(urlToCVEData.rfind('/') + 1);
            std::string filepath = cacheDir + "/" + filename;

            // Check if the file already exists in the cache directory
            std::ifstream file(filepath);
            if (!file) {
                std::ofstream outfile(filepath, std::ofstream::binary);
                downloadFile(urlToCVEData, &outfile);
                outfile.close();
            }

            // Append the downloaded file path to the list
            downloadedFiles.push_back(filepath);
        }

        // Sort the downloaded files based on their filenames
        std::sort(downloadedFiles.begin(), downloadedFiles.end());

        // Print the downloaded files
        //std::cout << "Downloaded Files:" << std::endl;
        //for (const std::string& file : downloadedFiles) {
            //std::cout << file << std::endl;
        //}

	std::cout << "NVD CVE Data Downloaded and Stored. " << std::endl;
        //for (const std::string& file : downloadedFiles) {
            //std::cout << file << std::endl;
        //}

    }

private:
    std::string cacheDirPath;
    std::string cacheDirName;
    std::string cacheDir;
    CURL* session;

    int getCurrentYear() {
        std::time_t currentTime = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&currentTime); // Use currentTime
        return timeinfo->tm_year + 1900;
    }

    void downloadFile(const std::string& url, std::ofstream* file) {
        CURLcode res;
        curl_easy_setopt(session, CURLOPT_URL, url.c_str());
        curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, WriteToFileCallback);
        curl_easy_setopt(session, CURLOPT_WRITEDATA, file);
        res = curl_easy_perform(session);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to download file: %s", curl_easy_strerror(res));
        }
    }
};

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    NVD_Source downloader;
    downloader.downloadCVEData();
    curl_global_cleanup();
    return 0;
}

