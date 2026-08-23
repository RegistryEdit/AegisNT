#include "LicenseServer.h"
#include <iomanip>

using json = nlohmann::json;

// Global rate limiting and security state
std::map<std::string, RateLimitInfo> RateLimitMap;
std::mutex RateLimitMutex;

// Secret key for token signing (in production, load from secure config)
const std::string KTokenSecret = "AegisNT_License_Server_Secret_Key_2025";
const int64_t KTokenExpirySeconds = 86400; // 24 hours
const int KMaxRequestsPerWindow = 5;
const int KRateLimitWindowSeconds = 300; // 5 minutes

// Utility functions
std::string GetCurrentTimestamp() {
	auto Now = std::time(nullptr);
	auto Tm = *std::localtime(&Now);
	std::ostringstream Oss;
	Oss << std::put_time(&Tm, "%Y-%m-%d %H:%M:%S");
	return Oss.str();
}

void LogInfo(const std::string& Message) {
	std::cout << "[" << GetCurrentTimestamp() << "] [INFO] " << Message << std::endl;
}

void LogError(const std::string& Message) {
	std::cerr << "[" << GetCurrentTimestamp() << "] [ERROR] " << Message << std::endl;
}

std::string GetClientIP(const httplib::Request& Req) {
	// Try X-Forwarded-For first (for proxies)
	if (Req.has_header("X-Forwarded-For")) {
		return Req.get_header_value("X-Forwarded-For");
	}
	// Fallback to remote_addr
	return Req.remote_addr;
}

// ========== Security Function 1: PBKDF2 Password Hashing ==========
// Note: Input is already SHA-256 hashed from client, we apply PBKDF2 on top
std::string HashPassword(const std::string& SHA256Hash) {
	const int Iterations = 100000;
	const int KeyLength = 32;
	unsigned char Salt[16];
	unsigned char Hash[KeyLength];

	// Generate random salt
	if (RAND_bytes(Salt, sizeof(Salt)) != 1) {
		LogError("HashPassword: Failed to generate salt");
		return "";
	}

	// Perform PBKDF2-HMAC-SHA256 on the SHA256 hash
	if (PKCS5_PBKDF2_HMAC(SHA256Hash.c_str(), SHA256Hash.length(),
		Salt, sizeof(Salt), Iterations,
		EVP_sha256(), KeyLength, Hash) != 1) {
		LogError("HashPassword: PBKDF2 failed");
		return "";
	}

	// Encode salt and hash as hex string: salt$hash
	std::ostringstream Oss;
	for (int I = 0; I < sizeof(Salt); ++I) {
		Oss << std::hex << std::setw(2) << std::setfill('0') << (int)Salt[I];
	}
	Oss << "$";
	for (int I = 0; I < KeyLength; ++I) {
		Oss << std::hex << std::setw(2) << std::setfill('0') << (int)Hash[I];
	}

	return Oss.str();
}

bool VerifyPassword(const std::string& SHA256Hash, const std::string& StoredHash) {
	const int Iterations = 100000;
	const int KeyLength = 32;

	// Parse stored hash: salt$hash
	size_t DollarPos = StoredHash.find('$');
	if (DollarPos == std::string::npos || DollarPos != 32) {
		LogError("VerifyPassword: Invalid hash format");
		return false;
	}

	std::string SaltHex = StoredHash.substr(0, 32);
	std::string HashHex = StoredHash.substr(33);

	// Decode salt from hex
	unsigned char Salt[16];
	for (int I = 0; I < 16; ++I) {
		std::string ByteStr = SaltHex.substr(I * 2, 2);
		Salt[I] = (unsigned char)strtol(ByteStr.c_str(), nullptr, 16);
	}

	// Compute hash with the same salt
	unsigned char ComputedHash[KeyLength];
	if (PKCS5_PBKDF2_HMAC(SHA256Hash.c_str(), SHA256Hash.length(),
		Salt, sizeof(Salt), Iterations,
		EVP_sha256(), KeyLength, ComputedHash) != 1) {
		LogError("VerifyPassword: PBKDF2 failed");
		return false;
	}

	// Compare computed hash with stored hash
	std::ostringstream Oss;
	for (int I = 0; I < KeyLength; ++I) {
		Oss << std::hex << std::setw(2) << std::setfill('0') << (int)ComputedHash[I];
	}

	return (Oss.str() == HashHex);
}

// ========== Security Function 2: HMAC-SHA256 Token Authentication ==========
std::string GenerateToken(const std::string& UserName, int UserType) {
	auto Now = std::chrono::system_clock::now();
	auto Expiry = Now + std::chrono::seconds(KTokenExpirySeconds);
	int64_t ExpiryTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
		Expiry.time_since_epoch()).count();

	// Payload: username|usertype|expiry
	std::string Payload = UserName + "|" + std::to_string(UserType) + "|" + std::to_string(ExpiryTimestamp);

	// Compute HMAC-SHA256 signature
	unsigned char Signature[EVP_MAX_MD_SIZE];
	unsigned int SigLen = 0;

	HMAC(EVP_sha256(), KTokenSecret.c_str(), KTokenSecret.length(),
		(const unsigned char*)Payload.c_str(), Payload.length(),
		Signature, &SigLen);

	// Encode signature as hex
	std::ostringstream SigHex;
	for (unsigned int I = 0; I < SigLen; ++I) {
		SigHex << std::hex << std::setw(2) << std::setfill('0') << (int)Signature[I];
	}

	// Token format: payload.signature
	return Payload + "." + SigHex.str();
}

bool VerifyToken(const std::string& Token, TokenPayload& OutPayload) {
	// Parse token: payload.signature
	size_t DotPos = Token.rfind('.');
	if (DotPos == std::string::npos) {
		LogError("VerifyToken: Invalid token format");
		return false;
	}

	std::string Payload = Token.substr(0, DotPos);
	std::string SignatureHex = Token.substr(DotPos + 1);

	// Verify signature
	unsigned char ComputedSig[EVP_MAX_MD_SIZE];
	unsigned int SigLen = 0;

	HMAC(EVP_sha256(), KTokenSecret.c_str(), KTokenSecret.length(),
		(const unsigned char*)Payload.c_str(), Payload.length(),
		ComputedSig, &SigLen);

	std::ostringstream ComputedSigHex;
	for (unsigned int I = 0; I < SigLen; ++I) {
		ComputedSigHex << std::hex << std::setw(2) << std::setfill('0') << (int)ComputedSig[I];
	}

	if (ComputedSigHex.str() != SignatureHex) {
		LogError("VerifyToken: Invalid signature");
		return false;
	}

	// Parse payload: username|usertype|expiry
	size_t FirstPipe = Payload.find('|');
	size_t SecondPipe = Payload.rfind('|');
	if (FirstPipe == std::string::npos || SecondPipe == std::string::npos || FirstPipe == SecondPipe) {
		LogError("VerifyToken: Invalid payload format");
		return false;
	}

	OutPayload.UserName = Payload.substr(0, FirstPipe);
	OutPayload.UserType = std::stoi(Payload.substr(FirstPipe + 1, SecondPipe - FirstPipe - 1));
	OutPayload.ExpiresAt = std::stoll(Payload.substr(SecondPipe + 1));

	// Check expiry
	auto Now = std::chrono::system_clock::now();
	int64_t CurrentTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
		Now.time_since_epoch()).count();

	if (CurrentTimestamp > OutPayload.ExpiresAt) {
		LogError("VerifyToken: Token expired");
		return false;
	}

	return true;
}

// ========== Security Function 3: Operation Logging ==========
void LogOperation(const std::string& Operation, const std::string& UserName,
	const std::string& TargetUser, const std::string& IPAddress, bool Success) {
	sqlite3* DB;
	if (sqlite3_open("LicenseServer.db", &DB) != SQLITE_OK) {
		LogError("LogOperation: Failed to open database");
		return;
	}

	// Create OperationLogs table if not exists
	std::string CreateTableSql = "CREATE TABLE IF NOT EXISTS OperationLogs ("
		"ID INTEGER PRIMARY KEY AUTOINCREMENT,"
		"Timestamp TEXT NOT NULL,"
		"Operation TEXT NOT NULL,"
		"UserName TEXT NOT NULL,"
		"TargetUser TEXT,"
		"IPAddress TEXT NOT NULL,"
		"Success INTEGER NOT NULL);";

	char* ErrMsg;
	if (sqlite3_exec(DB, CreateTableSql.c_str(), NULL, 0, &ErrMsg) != SQLITE_OK) {
		LogError("LogOperation: Failed to create table - " + std::string(ErrMsg));
		sqlite3_free(ErrMsg);
		sqlite3_close(DB);
		return;
	}

	// Insert log entry
	sqlite3_stmt* Stmt;
	std::string InsertSql = "INSERT INTO OperationLogs (Timestamp, Operation, UserName, TargetUser, IPAddress, Success) "
		"VALUES (?, ?, ?, ?, ?, ?);";

	if (sqlite3_prepare_v2(DB, InsertSql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
		LogError("LogOperation: Failed to prepare statement");
		sqlite3_close(DB);
		return;
	}

	sqlite3_bind_text(Stmt, 1, GetCurrentTimestamp().c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(Stmt, 2, Operation.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(Stmt, 3, UserName.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(Stmt, 4, TargetUser.empty() ? NULL : TargetUser.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(Stmt, 5, IPAddress.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_int(Stmt, 6, Success ? 1 : 0);

	if (sqlite3_step(Stmt) == SQLITE_DONE) {
		LogInfo("LogOperation: Logged operation '" + Operation + "' for user '" + UserName + "' from IP " + IPAddress);
	}
	else {
		LogError("LogOperation: Failed to insert log entry");
	}

	sqlite3_finalize(Stmt);
	sqlite3_close(DB);
}

// ========== Security Function 4: Rate Limiting ==========
bool CheckRateLimit(const std::string& IPAddress) {
	std::lock_guard<std::mutex> Lock(RateLimitMutex);

	auto Now = std::chrono::system_clock::now();

	// Check if IP exists in map
	if (RateLimitMap.find(IPAddress) == RateLimitMap.end()) {
		// New IP, initialize
		RateLimitMap[IPAddress] = { 1, Now };
		return true;
	}

	RateLimitInfo& Info = RateLimitMap[IPAddress];

	// Check if window expired
	auto Elapsed = std::chrono::duration_cast<std::chrono::seconds>(Now - Info.WindowStart).count();
	if (Elapsed >= KRateLimitWindowSeconds) {
		// Reset window
		Info.RequestCount = 1;
		Info.WindowStart = Now;
		return true;
	}

	// Within window, check count
	if (Info.RequestCount >= KMaxRequestsPerWindow) {
		LogError("CheckRateLimit: Rate limit exceeded for IP " + IPAddress + " (" + std::to_string(Info.RequestCount) + " requests in " + std::to_string(Elapsed) + "s)");
		return false;
	}

	// Increment count
	Info.RequestCount++;
	return true;
}

// ========== Database Helper Functions ==========
bool QueryUser(const std::string& Username, UserInfo& OutUser) {
	LogInfo("QueryUser: Searching for user '" + Username + "'");
	sqlite3* DB;
	if (sqlite3_open("LicenseServer.db", &DB) != SQLITE_OK) {
		LogError("QueryUser: Failed to open database");
		return false;
	}

	sqlite3_stmt* Stmt;
	std::string Sql = "SELECT UserName, UserType, PasswordHash FROM Users WHERE UserName = ?;";

	if (sqlite3_prepare_v2(DB, Sql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
		LogError("QueryUser: Failed to prepare statement");
		sqlite3_close(DB);
		return false;
	}

	sqlite3_bind_text(Stmt, 1, Username.c_str(), -1, SQLITE_STATIC);

	bool Found = false;
	if (sqlite3_step(Stmt) == SQLITE_ROW) {
		OutUser.UserName = reinterpret_cast<const char*>(sqlite3_column_text(Stmt, 0));
		OutUser.UserType = sqlite3_column_int(Stmt, 1);
		OutUser.PasswordHash = reinterpret_cast<const char*>(sqlite3_column_text(Stmt, 2));
		Found = true;
		LogInfo("QueryUser: User '" + Username + "' found (UserType=" + std::to_string(OutUser.UserType) + ")");
	}
	else {
		LogInfo("QueryUser: User '" + Username + "' not found");
	}

	sqlite3_finalize(Stmt);
	sqlite3_close(DB);
	return Found;
}

bool InsertUser(const UserInfo& User) {
	LogInfo("InsertUser: Attempting to insert user '" + User.UserName + "' (UserType=" + std::to_string(User.UserType) + ")");
	sqlite3* DB;
	if (sqlite3_open("LicenseServer.db", &DB) != SQLITE_OK) {
		LogError("InsertUser: Failed to open database");
		return false;
	}

	sqlite3_stmt* Stmt;
	std::string Sql = "INSERT INTO Users (UserName, UserType, PasswordHash) VALUES (?, ?, ?);";

	if (sqlite3_prepare_v2(DB, Sql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
		LogError("InsertUser: Failed to prepare statement");
		sqlite3_close(DB);
		return false;
	}

	sqlite3_bind_text(Stmt, 1, User.UserName.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_int(Stmt, 2, User.UserType);
	sqlite3_bind_text(Stmt, 3, User.PasswordHash.c_str(), -1, SQLITE_STATIC);

	bool Success = (sqlite3_step(Stmt) == SQLITE_DONE);

	if (Success) {
		LogInfo("InsertUser: User '" + User.UserName + "' inserted successfully");
	}
	else {
		LogError("InsertUser: Failed to insert user '" + User.UserName + "' - " + std::string(sqlite3_errmsg(DB)));
	}

	sqlite3_finalize(Stmt);
	sqlite3_close(DB);
	return Success;
}

bool UpdatePassword(const std::string& Username, const std::string& NewPasswordHash) {
	LogInfo("UpdatePassword: Updating password for user '" + Username + "'");
	sqlite3* DB;
	if (sqlite3_open("LicenseServer.db", &DB) != SQLITE_OK) {
		LogError("UpdatePassword: Failed to open database");
		return false;
	}

	sqlite3_stmt* Stmt;
	std::string Sql = "UPDATE Users SET PasswordHash = ? WHERE UserName = ?;";

	if (sqlite3_prepare_v2(DB, Sql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
		LogError("UpdatePassword: Failed to prepare statement");
		sqlite3_close(DB);
		return false;
	}

	sqlite3_bind_text(Stmt, 1, NewPasswordHash.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(Stmt, 2, Username.c_str(), -1, SQLITE_STATIC);

	bool Success = (sqlite3_step(Stmt) == SQLITE_DONE);

	if (Success) {
		LogInfo("UpdatePassword: Password updated successfully for user '" + Username + "'");
	}
	else {
		LogError("UpdatePassword: Failed to update password for user '" + Username + "'");
	}

	sqlite3_finalize(Stmt);
	sqlite3_close(DB);
	return Success;
}

bool UpdateUserType(const std::string& Username, int NewUserType) {
	LogInfo("UpdateUserType: Updating UserType for user '" + Username + "' to " + std::to_string(NewUserType));
	sqlite3* DB;
	if (sqlite3_open("LicenseServer.db", &DB) != SQLITE_OK) {
		LogError("UpdateUserType: Failed to open database");
		return false;
	}

	sqlite3_stmt* Stmt;
	std::string Sql = "UPDATE Users SET UserType = ? WHERE UserName = ?;";

	if (sqlite3_prepare_v2(DB, Sql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
		LogError("UpdateUserType: Failed to prepare statement");
		sqlite3_close(DB);
		return false;
	}

	sqlite3_bind_int(Stmt, 1, NewUserType);
	sqlite3_bind_text(Stmt, 2, Username.c_str(), -1, SQLITE_STATIC);

	bool Success = (sqlite3_step(Stmt) == SQLITE_DONE);

	if (Success) {
		LogInfo("UpdateUserType: UserType updated successfully for user '" + Username + "'");
	}
	else {
		LogError("UpdateUserType: Failed to update UserType for user '" + Username + "'");
	}

	sqlite3_finalize(Stmt);
	sqlite3_close(DB);
	return Success;
}

bool UserExists(const std::string& Username) {
	UserInfo Temp;
	return QueryUser(Username, Temp);
}

void InitDatabase() {
	LogInfo("InitDatabase: Starting database initialization");
	sqlite3* DB;
	int Exit = 0;
	Exit = sqlite3_open("LicenseServer.db", &DB);
	if (Exit) {
		LogError("InitDatabase: Error opening database - " + std::string(sqlite3_errmsg(DB)));
		return;
	}
	else {
		LogInfo("InitDatabase: Database opened successfully");
	}

	// Create Users table with PasswordHash column
	std::string Sql = "CREATE TABLE IF NOT EXISTS Users ("
		"UserName TEXT PRIMARY KEY NOT NULL,"
		"UserType INT NOT NULL,"
		"PasswordHash TEXT NOT NULL);";
	char* ErrMsg;
	Exit = sqlite3_exec(DB, Sql.c_str(), NULL, 0, &ErrMsg);
	if (Exit != SQLITE_OK) {
		LogError("InitDatabase: Error creating table - " + std::string(ErrMsg));
		sqlite3_free(ErrMsg);
	}
	else {
		LogInfo("InitDatabase: Users table created or already exists");
	}
	sqlite3_close(DB);

	// Create default admin account if not exists
	if (!UserExists("RegistryEdit")) {
		UserInfo Admin;
		Admin.UserName = "RegistryEdit";
		Admin.UserType = 1; // Administrator
		Admin.PasswordHash = HashPassword("kaidi004");

		if (InsertUser(Admin)) {
			LogInfo("InitDatabase: Default admin account 'RegistryEdit' created successfully");
		}
		else {
			LogError("InitDatabase: Failed to create default admin account");
		}
	}
	else {
		LogInfo("InitDatabase: Default admin account 'RegistryEdit' already exists");
	}
}

// ========== Main Server ==========
auto main() -> int {
	LogInfo("=== LicenseServer Starting ===");
	LogInfo("Security Features: PBKDF2 Hashing, HMAC-SHA256 Tokens, Operation Logs, Rate Limiting");

	if (!std::filesystem::exists("LicenseServer.db")) {
		LogInfo("Database file not found, initializing new database");
		InitDatabase();
	}
	else {
		LogInfo("Database file found");
		// Still check for default admin
		if (!UserExists("RegistryEdit")) {
			UserInfo Admin;
			Admin.UserName = "RegistryEdit";
			Admin.UserType = 1;
			Admin.PasswordHash = HashPassword("kaidi004");
			InsertUser(Admin);
		}
	}

	httplib::Server Svr;

	// ========== POST /Login Endpoint ==========
	Svr.Post("/Login", [](const httplib::Request& Req, httplib::Response& Res) {
		std::string ClientIP = GetClientIP(Req);
		LogInfo("=== /Login Request from IP: " + ClientIP + " ===");

		// Rate limiting
		if (!CheckRateLimit(ClientIP)) {
			json Error = { {"success", false}, {"message", "Too many requests. Please try again later."} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 429;
			LogOperation("Login", "unknown", "", ClientIP, false);
			return;
		}

		json ReqJson;
		try {
			ReqJson = json::parse(Req.body);
		}
		catch (...) {
			LogError("/Login: Invalid JSON format");
			json Error = { {"success", false}, {"message", "Invalid JSON"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		std::string Username = ReqJson.value("UserName", "");
		std::string Password = ReqJson.value("Password", "");

		if (Username.empty() || Password.empty()) {
			LogError("/Login: Missing UserName or Password");
			json Error = { {"success", false}, {"message", "Missing UserName or Password"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		LogInfo("/Login: Attempting login for user '" + Username + "'");
		UserInfo User;

		if (!QueryUser(Username, User)) {
			LogError("/Login: User '" + Username + "' does not exist");
			json Error = { {"success", false}, {"message", "User does not exist"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("Login", Username, "", ClientIP, false);
			return;
		}

		// Verify password using PBKDF2
		if (!VerifyPassword(Password, User.PasswordHash)) {
			LogError("/Login: Invalid password for user '" + Username + "'");
			json Error = { {"success", false}, {"message", "Invalid password"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("Login", Username, "", ClientIP, false);
			return;
		}

		// Generate token
		std::string Token = GenerateToken(User.UserName, User.UserType);

		LogInfo("/Login: User '" + Username + "' logged in successfully (UserType=" + std::to_string(User.UserType) + ")");
		LogOperation("Login", Username, "", ClientIP, true);

		json Response = {
			{"success", true},
			{"message", "Login successful"},
			{"data", {
				{"UserName", User.UserName},
				{"UserType", User.UserType},
				{"Token", Token}
			}}
		};

		Res.set_content(Response.dump(), "application/json");
		Res.status = 200;
		});

	// ========== POST /Register Endpoint ==========
	Svr.Post("/Register", [](const httplib::Request& Req, httplib::Response& Res) {
		std::string ClientIP = GetClientIP(Req);
		LogInfo("=== /Register Request from IP: " + ClientIP + " ===");

		// Rate limiting
		if (!CheckRateLimit(ClientIP)) {
			json Error = { {"success", false}, {"message", "Too many requests. Please try again later."} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 429;
			return;
		}

		json ReqJson;
		try {
			ReqJson = json::parse(Req.body);
		}
		catch (...) {
			LogError("/Register: Invalid JSON format");
			json Error = { {"success", false}, {"message", "Invalid JSON"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		std::string Username = ReqJson.value("UserName", "");
		std::string Password = ReqJson.value("Password", "");

		if (Username.empty() || Password.empty()) {
			LogError("/Register: Missing UserName or Password");
			json Error = { {"success", false}, {"message", "Missing UserName or Password"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		// Force UserType to 0 (Regular User) - only admins can create admin accounts via ChangeUserType
		int UserType = 0;

		LogInfo("/Register: Attempting to register user '" + Username + "' as Regular User");

		if (UserExists(Username)) {
			LogError("/Register: Username '" + Username + "' already exists");
			json Error = { {"success", false}, {"message", "Username already exists"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 409;
			LogOperation("Register", Username, "", ClientIP, false);
			return;
		}

		UserInfo NewUser;
		NewUser.UserName = Username;
		NewUser.UserType = UserType;
		NewUser.PasswordHash = HashPassword(Password);

		if (!InsertUser(NewUser)) {
			LogError("/Register: Failed to insert user into database");
			json Error = { {"success", false}, {"message", "Failed to register user"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 500;
			LogOperation("Register", Username, "", ClientIP, false);
			return;
		}

		LogInfo("/Register: User '" + Username + "' registered successfully as Regular User");
		LogOperation("Register", Username, "", ClientIP, true);

		json Response = {
			{"success", true},
			{"message", "User registered successfully"}
		};

		Res.set_content(Response.dump(), "application/json");
		Res.status = 200;
		});

	// ========== POST /ChangePassword Endpoint ==========
	Svr.Post("/ChangePassword", [](const httplib::Request& Req, httplib::Response& Res) {
		std::string ClientIP = GetClientIP(Req);
		LogInfo("=== /ChangePassword Request from IP: " + ClientIP + " ===");

		// Rate limiting
		if (!CheckRateLimit(ClientIP)) {
			json Error = { {"success", false}, {"message", "Too many requests. Please try again later."} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 429;
			return;
		}

		json ReqJson;
		try {
			ReqJson = json::parse(Req.body);
		}
		catch (...) {
			LogError("/ChangePassword: Invalid JSON format");
			json Error = { {"success", false}, {"message", "Invalid JSON"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		std::string Username = ReqJson.value("UserName", "");
		std::string OldPassword = ReqJson.value("OldPassword", "");
		std::string NewPassword = ReqJson.value("NewPassword", "");

		if (Username.empty() || OldPassword.empty() || NewPassword.empty()) {
			LogError("/ChangePassword: Missing required fields");
			json Error = { {"success", false}, {"message", "Missing UserName, OldPassword, or NewPassword"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		LogInfo("/ChangePassword: Attempting to change password for user '" + Username + "'");
		UserInfo User;

		if (!QueryUser(Username, User)) {
			LogError("/ChangePassword: User '" + Username + "' does not exist");
			json Error = { {"success", false}, {"message", "User does not exist"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("ChangePassword", Username, "", ClientIP, false);
			return;
		}

		if (!VerifyPassword(OldPassword, User.PasswordHash)) {
			LogError("/ChangePassword: Old password is incorrect for user '" + Username + "'");
			json Error = { {"success", false}, {"message", "Old password is incorrect"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("ChangePassword", Username, "", ClientIP, false);
			return;
		}

		std::string NewPasswordHash = HashPassword(NewPassword);
		if (!UpdatePassword(Username, NewPasswordHash)) {
			LogError("/ChangePassword: Failed to update password in database");
			json Error = { {"success", false}, {"message", "Failed to update password"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 500;
			LogOperation("ChangePassword", Username, "", ClientIP, false);
			return;
		}

		LogInfo("/ChangePassword: Password changed successfully for user '" + Username + "'");
		LogOperation("ChangePassword", Username, "", ClientIP, true);

		json Response = {
			{"success", true},
			{"message", "Password changed successfully"}
		};

		Res.set_content(Response.dump(), "application/json");
		Res.status = 200;
		});

	// ========== POST /ChangeUserType Endpoint (Enhanced Security) ==========
	Svr.Post("/ChangeUserType", [](const httplib::Request& Req, httplib::Response& Res) {
		std::string ClientIP = GetClientIP(Req);
		LogInfo("=== /ChangeUserType Request from IP: " + ClientIP + " ===");

		// Rate limiting (stricter for admin operations)
		if (!CheckRateLimit(ClientIP)) {
			json Error = { {"success", false}, {"message", "Too many requests. Please try again later."} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 429;
			return;
		}

		json ReqJson;
		try {
			ReqJson = json::parse(Req.body);
		}
		catch (...) {
			LogError("/ChangeUserType: Invalid JSON format");
			json Error = { {"success", false}, {"message", "Invalid JSON"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		std::string AdminName = ReqJson.value("AdminName", "");
		std::string AdminPassword = ReqJson.value("AdminPassword", "");
		std::string TargetUserName = ReqJson.value("TargetUserName", "");
		int NewUserType = ReqJson.value("NewUserType", -1);

		if (AdminName.empty() || AdminPassword.empty() || TargetUserName.empty() || NewUserType == -1) {
			LogError("/ChangeUserType: Missing required fields");
			json Error = { {"success", false}, {"message", "Missing AdminName, AdminPassword, TargetUserName, or NewUserType"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		if (NewUserType != 0 && NewUserType != 1) {
			LogError("/ChangeUserType: Invalid NewUserType (" + std::to_string(NewUserType) + ")");
			json Error = { {"success", false}, {"message", "Invalid NewUserType (must be 0 or 1)"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 400;
			return;
		}

		LogInfo("/ChangeUserType: Admin '" + AdminName + "' attempting to change UserType for '" + TargetUserName + "' to " + std::to_string(NewUserType));

		// Verify admin credentials
		UserInfo Admin;
		if (!QueryUser(AdminName, Admin)) {
			LogError("/ChangeUserType: Admin user '" + AdminName + "' does not exist");
			json Error = { {"success", false}, {"message", "Admin user does not exist"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, false);
			return;
		}

		if (!VerifyPassword(AdminPassword, Admin.PasswordHash)) {
			LogError("/ChangeUserType: Invalid admin password for '" + AdminName + "'");
			json Error = { {"success", false}, {"message", "Invalid admin password"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 401;
			LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, false);
			return;
		}

		// Check if admin has administrator privileges
		if (Admin.UserType != 1) {
			LogError("/ChangeUserType: User '" + AdminName + "' is not an administrator (UserType=" + std::to_string(Admin.UserType) + ")");
			json Error = { {"success", false}, {"message", "Permission denied: You are not an administrator"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 403;
			LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, false);
			return;
		}

		// Check if target user exists
		if (!UserExists(TargetUserName)) {
			LogError("/ChangeUserType: Target user '" + TargetUserName + "' does not exist");
			json Error = { {"success", false}, {"message", "Target user does not exist"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 404;
			LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, false);
			return;
		}

		// Update target user's UserType
		if (!UpdateUserType(TargetUserName, NewUserType)) {
			LogError("/ChangeUserType: Failed to update UserType in database");
			json Error = { {"success", false}, {"message", "Failed to update UserType"} };
			Res.set_content(Error.dump(), "application/json");
			Res.status = 500;
			LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, false);
			return;
		}

		LogInfo("/ChangeUserType: UserType changed successfully for user '" + TargetUserName + "' to " + std::to_string(NewUserType) + " by admin '" + AdminName + "'");
		LogOperation("ChangeUserType", AdminName, TargetUserName, ClientIP, true);

		json Response = {
			{"success", true},
			{"message", "UserType changed successfully"}
		};

		Res.set_content(Response.dump(), "application/json");
		Res.status = 200;
		});

	// Start the server
	LogInfo("Server configured with all endpoints:");
	LogInfo("  - POST /Login (with token generation)");
	LogInfo("  - POST /Register");
	LogInfo("  - POST /ChangePassword");
	LogInfo("  - POST /ChangeUserType (admin verification required)");
	LogInfo("Starting server on 0.0.0.0:8888...");

	if (!Svr.listen("0.0.0.0", 8888)) {
		LogError("Failed to start server on port 8888");
		return 1;
	}

	return 0;
}
