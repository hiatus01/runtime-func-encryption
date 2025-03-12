#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>

class FunctionEncrypter {
private:
    struct EncryptedFunction {
        std::vector<BYTE> encryptedBytes;
        std::vector<BYTE> originalBytes; // Added to store original bytes for comparison
        PBYTE originalAddress;
        DWORD size;
        BYTE xorKey[16];
    };

    std::map<std::string, EncryptedFunction> encryptedFunctions;

    void XorCrypt(std::vector<BYTE>& bytes, BYTE* key, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            bytes[i] ^= key[i % 16];
        }
    }

    void GenerateKeyFromString(const std::string& id, BYTE* key) {
        for (size_t i = 0; i < 16; i++) {
            key[i] = (BYTE)(id[i % id.length()] + i);
        }
    }

    // Debug function to print opcodes
    void PrintOpcodes(const std::string& id, const std::vector<BYTE>& bytes, const char* label) {
        printf("%s Opcodes for '%s' (%d bytes):\n", label, id.c_str(), (int)bytes.size());
        for (size_t i = 0; i < bytes.size(); i++) {
            printf("%02X ", bytes[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");
    }

public:
    bool EncryptFunction(const std::string& id, PVOID functionStart, PVOID functionEnd) {
        DWORD size = GetFuncSize((DWORD*)functionStart, (DWORD*)functionEnd);
        if (size == 0) return false;

        EncryptedFunction encFunc;
        
        // Store original bytes
        encFunc.originalBytes.resize(size);
        memcpy(encFunc.originalBytes.data(), functionStart, size);
        
        // Generate key and encrypt
        GenerateKeyFromString(id, encFunc.xorKey);
        encFunc.encryptedBytes = encFunc.originalBytes;
        XorCrypt(encFunc.encryptedBytes, encFunc.xorKey, size);
        
        // Print opcodes for comparison
        PrintOpcodes(id, encFunc.originalBytes, "Unencrypted");
        PrintOpcodes(id, encFunc.encryptedBytes, "Encrypted");

        encFunc.originalAddress = (PBYTE)functionStart;
        encFunc.size = size;
        encryptedFunctions[id] = encFunc;

        DWORD oldProtect;
        VirtualProtect(functionStart, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memset(functionStart, 0x90, size);
        
        return true;
    }

    bool RunFunction(const std::string& id) {
        auto it = encryptedFunctions.find(id);
        if (it == encryptedFunctions.end()) return false;

        EncryptedFunction& encFunc = it->second;
        std::vector<BYTE> decryptedBytes = encFunc.encryptedBytes;
        XorCrypt(decryptedBytes, encFunc.xorKey, encFunc.size);

        DWORD oldProtect;
        VirtualProtect(encFunc.originalAddress, encFunc.size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(encFunc.originalAddress, decryptedBytes.data(), encFunc.size);

        __try {
            ((void(*)())encFunc.originalAddress)();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            memcpy(encFunc.originalAddress, encFunc.encryptedBytes.data(), encFunc.size);
            return false;
        }

        memcpy(encFunc.originalAddress, encFunc.encryptedBytes.data(), encFunc.size);
        VirtualProtect(encFunc.originalAddress, encFunc.size, oldProtect, &oldProtect);
        return true;
    }
};

// Example usage
void TestFunction() {
    MessageBox(0, L"Hello From Testfunction!", L"Test", 0);
}

void FunctionStub() { return; }

DWORD GetFuncSize(DWORD* Function, DWORD* StubFunction) {
    DWORD dwFunctionSize = 0, dwOldProtect;
    DWORD *fnA = NULL, *fnB = NULL;

    fnA = (DWORD *)Function;
    fnB = (DWORD *)StubFunction;
    dwFunctionSize = (fnB - fnA);
    VirtualProtect(fnA, dwFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    return dwFunctionSize;
}

int main() {
    FunctionEncrypter encrypter;
    
    // Encrypt and show opcodes
    encrypter.EncryptFunction("test1", TestFunction, FunctionStub);
    
    // Run the function
    encrypter.RunFunction("test1");
    
    return 0;
}
