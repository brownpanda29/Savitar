

---

# Ransomware PoC - Recursive File Encryption with AES-256
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



## Overview
This is a **proof of concept** (PoC) ransomware project written in **C++**. The program recursively searches the entire file system for files with specified extensions, uploads 10 randomly selected files to a remote server or API, and then encrypts the rest using **AES-256 encryption**. 

**Disclaimer**: This project is strictly for educational and research purposes. Unauthorized use is illegal and unethical.

---

## Workflow
1. **File Search**:  
   - The program recursively searches the entire file system.  
   - It filters files by specified extensions and generates a list of matching files.

2. **File Upload**:  
   - From the list of matching files, 10 files are randomly selected.  
   - These files are uploaded to a remote server or API for demonstration purposes.

3. **File Encryption**:  
   - All files in the list are encrypted using **AES-256 encryption**.  
   - The encryption key is fixed and must be set manually within the source code.

---

## Prerequisites
- **C++17 or higher**
- Compiler:
  - Windows: MinGW, MSVC (Visual Studio)
  - Unix-like: GCC or Clang
- Cryptography library (e.g., OpenSSL) for AES-256 encryption.
- API endpoint or server setup for file uploads.

---

## Compilation
### On Windows:
```bash
g++ -std=c++17 file_search.cpp -lshlwapi
```

### On Unix-like Systems:
```bash
g++ -std=c++17 file_search.cpp
```

---

## Usage
1. **Run the executable**:
   ```bash
   ./ransomware
   ```
   No target directory is required since the program automatically searches the entire file system.

2. **Configuration**:
   - **File Extensions**: Set the extensions to target in the source code.
   - **Encryption Key**: Manually set the AES-256 encryption key in the source code.
   - **API/Server URL**: Configure the upload server or API endpoint in the source code.

---

## Disclaimer
This project is intended for **educational purposes only**. Unauthorized use of this software against third-party systems is illegal and punishable under applicable laws. Always ensure you have explicit permission before testing this tool in any environment. The authors disclaim any responsibility for misuse of this software.

By using this repository, you agree to comply with applicable law I won't be liable for anything. ✌️
