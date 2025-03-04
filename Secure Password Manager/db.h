#pragma once
#include "json/json.h"
#include "sqlite3.h"
#include "user.h"

class DB {
	const std::string dbFile = "password_manager.db";
	sqlite3* db;
	User& user;
public:
	explicit DB(User& userRef); //defined in db.cpp
	~DB(); //dont have a use case for this yet

	sqlite3* getSQLiteDB() const { return db; }

	void login();

	bool userExists();

	void registerUser();

	int getUserId();
};