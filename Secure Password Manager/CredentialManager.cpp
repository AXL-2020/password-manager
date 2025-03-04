#include "CredentialManager.h"
#include <sodium.h>
#include <iostream>
#include <vector>
#include <cstring> // for memcpy

// For demonstration, we initialize the key to a constant value.
// In production, use a key derivation function to generate a persistent key.
void CredentialManager::initializeKey(const std::string& masterPassword) {
    // Generate a random salt (this should be stored and reused for the same user)
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    if (sodium_mlock(key, sizeof(key)) != 0) 
        std::cerr << "Failed to lock memory for encryption key." << std::endl;

    // Derive the encryption key from the user's master password
    if (crypto_pwhash(key, sizeof(key), masterPassword.c_str(), masterPassword.size(),
        salt, crypto_pwhash_ALG_ARGON2ID13,
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        std::cerr << "Error deriving encryption key." << std::endl;
        std::memset(key, 0, sizeof(key)); // Clear key on failure
    }
}

void CredentialManager::clearKey() {
    sodium_memzero(key, sizeof(key));
}

CredentialManager::CredentialManager(sqlite3* db, int userId, const std::string& masterPassword)
    : db(db), userId(userId)
{
    if (sodium_init() < 0) 
        std::cerr << "Libsodium initialization failed!" << std::endl;
    
    initializeKey(masterPassword);
}

CredentialManager::~CredentialManager() {
    clearKey();
}

// Encrypts a plaintext password.
// The function generates a random nonce, encrypts the plaintext using crypto_secretbox_easy,
// and then concatenates the nonce and ciphertext. The combined data is base64 encoded for storage.
std::string CredentialManager::encryptPassword(const std::string& plain) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // Prepare buffer for ciphertext: plaintext length + MAC bytes.
    std::vector<unsigned char> ciphertext(plain.size() + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(ciphertext.data(),
        reinterpret_cast<const unsigned char*>(plain.data()),
        plain.size(),
        nonce,
        key) != 0) {
        std::cerr << "Encryption failed." << std::endl;
        return "";
    }

    // Combine nonce and ciphertext.
    std::vector<unsigned char> combined;
    combined.insert(combined.end(), nonce, nonce + crypto_secretbox_NONCEBYTES);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    // Base64 encode the combined buffer.
    size_t b64_max_len = sodium_base64_encoded_len(combined.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> b64(b64_max_len);
    sodium_bin2base64(b64.data(), b64_max_len, combined.data(), combined.size(), sodium_base64_VARIANT_ORIGINAL);

    return std::string(b64.data());
}

// Decrypts an encrypted password.
// The function decodes the base64 data, extracts the nonce and ciphertext, and then decrypts it.
std::string CredentialManager::decryptPassword(const std::string& encrypted) {
    // Base64 decode the combined data.
    std::vector<unsigned char> combined(encrypted.size());
    size_t combined_len;
    if (sodium_base642bin(combined.data(), combined.size(),
        encrypted.c_str(), encrypted.size(),
        nullptr, &combined_len, nullptr,
        sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::cerr << "Base64 decoding failed." << std::endl;
        return "";
    }
    if (combined_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        std::cerr << "Invalid encrypted data." << std::endl;
        return "";
    }

    // Extract the nonce.
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, combined.data(), crypto_secretbox_NONCEBYTES);

    // Extract the ciphertext.
    size_t ciphertext_len = combined_len - crypto_secretbox_NONCEBYTES;
    std::vector<unsigned char> ciphertext(ciphertext_len);
    memcpy(ciphertext.data(), combined.data() + crypto_secretbox_NONCEBYTES, ciphertext_len);

    // Prepare buffer for decrypted plaintext.
    std::vector<unsigned char> decrypted(ciphertext_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(),
        ciphertext.data(),
        ciphertext_len,
        nonce,
        key) != 0) {
        std::cerr << "Decryption failed." << std::endl;
        return "";
    }

    return std::string(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
}

// Adds a new credential for the specified service.
bool CredentialManager::addCredential(const std::string& service, const std::string& password) {
    std::string encrypted = encryptPassword(password);
    if (encrypted.empty()) {
        return false;
    }

    sqlite3_stmt* stmt;
    std::string query = "INSERT INTO credentials (user_id, service, encrypted_password) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing addCredential statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, encrypted.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error adding credential: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

// Retrieves and decrypts the credential for the specified service.
bool CredentialManager::getCredential(const std::string& service, std::string& password) {
    sqlite3_stmt* stmt;
    std::string query = "SELECT encrypted_password FROM credentials WHERE user_id = ? AND service = ?;";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing getCredential statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* encrypted = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string encryptedStr(encrypted);
        password = decryptPassword(encryptedStr);
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

// Updates the credential for the specified service with a new password.
bool CredentialManager::updateCredential(const std::string& service, const std::string& newPassword) {
    std::string encrypted = encryptPassword(newPassword);
    if (encrypted.empty()) {
        return false;
    }

    sqlite3_stmt* stmt;
    std::string query = "UPDATE credentials SET encrypted_password = ? WHERE user_id = ? AND service = ?;";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing updateCredential statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, encrypted.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, userId);
    sqlite3_bind_text(stmt, 3, service.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error updating credential: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

// Deletes the credential for the specified service.
bool CredentialManager::deleteCredential(const std::string& service) {
    sqlite3_stmt* stmt;
    std::string query = "DELETE FROM credentials WHERE user_id = ? AND service = ?;";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing deleteCredential statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error deleting credential: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}