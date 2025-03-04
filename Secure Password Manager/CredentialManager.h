#pragma once
#include <string>
#include "sqlite3.h"
#include <sodium/crypto_secretbox.h>

// The CredentialManager class handles encryption and CRUD operations for service credentials.
class CredentialManager {
    sqlite3* db;
    int userId;
    unsigned char key[crypto_secretbox_KEYBYTES];

    std::string encryptPassword(const std::string& plain);

    std::string decryptPassword(const std::string& encrypted);

    void initializeKey(const std::string& masterPassword);
    void clearKey();

public:
    CredentialManager(sqlite3* db, int userId, const std::string& masterPassword);
    ~CredentialManager();

    bool addCredential(const std::string& service, const std::string& password);
    bool getCredential(const std::string& service, std::string& password);
    bool updateCredential(const std::string& service, const std::string& newPassword);
    bool deleteCredential(const std::string& service);
    
};