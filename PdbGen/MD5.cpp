#include "MD5.h"
#include "Windows.h"
#include "Wincrypt.h"

using namespace std;

// Adapted from https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
vector<uint8_t> MD5::HashFile(const string& filename) {
    vector<uint8_t> result(16, 0x00);

    HANDLE file = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        HCRYPTPROV cryptProv = NULL;
        if (CryptAcquireContext(&cryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            HCRYPTHASH hash = NULL;
            if (CryptCreateHash(cryptProv, CALG_MD5, NULL, NULL, &hash)) {
                // Add data to the hash, 1k at a time
                BOOL success = FALSE;
                DWORD readBytes = 0;
                BYTE buffer[1024];
                while (success = ReadFile(file, buffer, 1024, &readBytes, NULL)) {
                    if (readBytes == 0) break;
                    if (!CryptHashData(hash, buffer, readBytes, NULL)) {
                        success = FALSE;
                        break;
                    }
                }
                if (success) {
                    DWORD hashSize = 16;
                    CryptGetHashParam(hash, HP_HASHVAL, result.data(), &hashSize, 0);
                }
            }
            CryptReleaseContext(cryptProv, NULL);
        }
        CloseHandle(file);
    }
    return result;
}
