#include "db.h"
#include "crypt.h"

DB::DB(User& userRef) : user(userRef), db(nullptr) {

    char* errMsg = nullptr;

    if (sqlite3_open(dbFile.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error opening database." << std::endl;
        db = nullptr;
        return;
    }
    const char* create_users_table = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);";
    const char* create_credentials_table = "CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, user_id INTEGER, service TEXT, encrypted_password TEXT, FOREIGN KEY(user_id) REFERENCES users(id));";
    
    if (sqlite3_exec(db, create_users_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating users table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }

    if (sqlite3_exec(db, create_credentials_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating credentials table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

DB::~DB() {
    if (db) {
        sqlite3_close(db);
        std::cout << "Database closed successfully.\n";
    }
}

bool DB::userExists() {
    if (!db)
        return false;

    sqlite3_stmt* stmt;

    std::string query = "SELECT COUNT(*) FROM users WHERE username = ?;";

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, user.getUsername().c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0)
        return true;

    sqlite3_finalize(stmt);
    return false;
}

void DB::registerUser() {
    if (!db)
        return;

    sqlite3_stmt* stmt;
    std::string query = "INSERT INTO users (username, password_hash) VALUES (?, ?);";

    std::string hashedPassword = hashPassword(user.getPassword());
    if (hashedPassword.empty()) {
        std::cerr << "Password hashing failed." << std::endl;
        return;
    }

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    sqlite3_bind_text(stmt, 1, user.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashedPassword.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_DONE)
        std::cout << "User registered successfully." << std::endl;
    else
        std::cerr << "Error registering user." << sqlite3_errmsg(db) << std::endl;

    sqlite3_finalize(stmt);
}

void DB::login() {
    if (!db)
        return;

    sqlite3_stmt* stmt;
    std::string query = "SELECT password_hash FROM users WHERE username = ?;";

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    sqlite3_bind_text(stmt, 1, user.getUsername().c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string storedHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        if (verifyPassword(storedHash, user.getPassword()))
            std::cout << "Login successful." << std::endl;
        else
            std::cerr << "Invalid password." << std::endl;

    }
    else
        std::cerr << "User not found." << std::endl;

    sqlite3_finalize(stmt);
}

int DB::getUserId() {
    sqlite3_stmt* stmt;
    std::string query = "SELECT id FROM users WHERE username = ?;";
    int userId = -1;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, user.getUsername().c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            userId = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return userId;
}