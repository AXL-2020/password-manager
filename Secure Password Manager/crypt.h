#pragma once
#include <iostream>
#include <sodium.h>

// Hashes the plain text password using Libsodium's crypto_pwhash API.
// Returns the encoded hash as a string. If hashing fails, an empty string is returned.
std::string hashPassword(const std::string& password);

// Verifies the provided plain text password against the stored encoded hash.
// Returns true if the password is correct, false otherwise.
bool verifyPassword(const std::string& hashedPassword, const std::string& password);