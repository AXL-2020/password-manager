#include "crypt.h"

std::string hashPassword(const std::string& password) {
    // Ensure Libsodium is initialized (sodium_init() returns -1 on failure)
    if (sodium_init() < 0) {
        std::cerr << "Libsodium initialization failed." << std::endl;
        return "";
    }

    // Libsodium requires an output buffer of size crypto_pwhash_STRBYTES.
    char hashed[crypto_pwhash_STRBYTES];

    // Use default interactive limits for operations and memory.
    if (crypto_pwhash_str(hashed, password.c_str(), password.size(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {

        std::cerr << "Error hashing password: out of memory or other error." << std::endl;
        return "";
    }

    return std::string(hashed);
}

bool verifyPassword(const std::string& hashedPassword, const std::string& password) {
    // Ensure Libsodium is initialized
    if (sodium_init() < 0) {
        std::cerr << "Libsodium initialization failed." << std::endl;
        return false;
    }

    // crypto_pwhash_str_verify returns 0 if verification succeeds.
    if (crypto_pwhash_str_verify(hashedPassword.c_str(), password.c_str(), password.size()) == 0)
        return true;

    return false;
}