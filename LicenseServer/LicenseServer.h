#pragma once
#include <httplib.h>
#include <string>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <random>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

typedef struct _UserInfo{
	std::string UserName;
	int UserType;
	std::string PasswordHash;
} UserInfo, * PUserInfo;

// JWT Token structure
struct TokenPayload {
	std::string UserName;
	int UserType;
	int64_t ExpiresAt;
};

// Function declarations
void InitDatabase();
bool QueryUser(const std::string& Username, UserInfo& OutUser);
bool InsertUser(const UserInfo& User);
bool UpdatePassword(const std::string& Username, const std::string& NewPasswordHash);
bool UpdateUserType(const std::string& Username, int NewUserType);
bool UserExists(const std::string& Username);
std::string GetCurrentTimestamp();
void LogInfo(const std::string& Message);
void LogError(const std::string& Message);

// Security functions
std::string HashPassword(const std::string& Password);
bool VerifyPassword(const std::string& Password, const std::string& Hash);
std::string GenerateToken(const std::string& UserName, int UserType);
bool VerifyToken(const std::string& Token, TokenPayload& OutPayload);
void LogOperation(const std::string& Operation, const std::string& UserName, 
                  const std::string& TargetUser, const std::string& IPAddress, bool Success);
std::string GetClientIP(const httplib::Request& Req);


