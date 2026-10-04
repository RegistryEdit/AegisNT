#include "AuthService.h"
#include "../Configuration/ConfigurationManager.h"
#include "../../AppContext.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QEventLoop>
#include <QJsonDocument>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace AegisNT {

// 前向声明辅助函数
extern void ShowSuccessNotice(QWidget *Parent, const QString &Title, const QString &Content);
extern void ShowErrorNotice(QWidget *Parent, const QString &Title, const QString &Content);

AuthService::AuthService() = default;

AuthService::~AuthService() = default;

QString AuthService::Sha256Hex(const QString &Input) {
    return QString(QCryptographicHash::hash(Input.toUtf8(),
                                           QCryptographicHash::Sha256)
                      .toHex());
}

QString AuthService::EncryptPassword(const QString &Password) {
    const QByteArray Raw = Password.toUtf8();
    DATA_BLOB In, Out;
    In.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(Raw.constData()));
    In.cbData = static_cast<DWORD>(Raw.size());

    if (!CryptProtectData(&In, L"AegisNT.Password", nullptr, nullptr, nullptr, 0, &Out))
        return QString();

    const QByteArray Blob(reinterpret_cast<const char *>(Out.pbData),
                         static_cast<int>(Out.cbData));
    LocalFree(Out.pbData);
    return QLatin1String("DPAPI:") + QString(Blob.toBase64());
}

QString AuthService::DecryptPassword(const QString &Encrypted) {
    if (Encrypted.startsWith(QLatin1String("DPAPI:"))) {
        const QByteArray Blob = QByteArray::fromBase64(Encrypted.mid(6).toUtf8());
        DATA_BLOB In, Out;
        In.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(Blob.constData()));
        In.cbData = static_cast<DWORD>(Blob.size());

        if (!CryptUnprotectData(&In, nullptr, nullptr, nullptr, nullptr, 0, &Out))
            return QString();

        const QString Plain = QString::fromUtf8(
            reinterpret_cast<const char *>(Out.pbData),
            static_cast<int>(Out.cbData));
        LocalFree(Out.pbData);
        return Plain;
    }

    // 旧格式：单字节 XOR + Base64（兼容性）
    QByteArray Data = QByteArray::fromBase64(Encrypted.toUtf8());
    const char Key = 0xAA;
    for (int I = 0; I < Data.size(); ++I)
        Data[I] = Data[I] ^ Key;
    return QString(Data);
}

QString AuthService::GetAuthServerAddress() const {
    ConfigurationManager &Config = GlobalConfiguration();
    QString Address = Config.LicenseServerAddress().trimmed();

    while (Address.endsWith('/'))
        Address.chop(1);

    if (Address.isEmpty())
        Address = "http://localhost:8888";

    return Address;
}

QJsonObject AuthService::SendAuthRequest(const QString &Endpoint,
                                        const QJsonObject &Payload,
                                        QString *ErrorMessage) {
    QNetworkAccessManager Manager;
    QNetworkRequest Request(QUrl(GetAuthServerAddress() + Endpoint));
    Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    Request.setTransferTimeout(6000);

    QNetworkReply *Reply = Manager.post(Request, QJsonDocument(Payload).toJson());
    QEventLoop Loop;
    QObject::connect(Reply, &QNetworkReply::finished, &Loop, &QEventLoop::quit);
    Loop.exec();

    QJsonObject Response;
    if (Reply->error() == QNetworkReply::NoError) {
        Response = QJsonDocument::fromJson(Reply->readAll()).object();
    } else {
        if (ErrorMessage)
            *ErrorMessage = Reply->errorString();
    }

    Reply->deleteLater();
    return Response;
}

void AuthService::HandleLoginSuccess(QWidget *NoticeParent,
                                    const QJsonObject &Data,
                                    const QString &Username,
                                    const QString &Password,
                                    bool RememberMe,
                                    bool AutoLogin) {
    const QString CleanUsername = Username.trimmed();
    const QString Title = Data["Title"].toString();
    const int UserType = Data["UserType"].toInt(-1);
    const QString Token = Data["Token"].toString().trimmed();

    if (CleanUsername.isEmpty() || Token.isEmpty() ||
        (UserType != 0 && UserType != 1)) {
        ConfigurationManager &Config = GlobalConfiguration();
        Config.SetValue("Account", "IsLoggedIn", false);
        Config.SetValue("Account", "Token", "");

        auto &Ctx = ApplicationContext();
        Ctx.Account = {};
        NotifyAccountSessionChanged();

        if (NoticeParent)
            ShowErrorNotice(NoticeParent, "Account",
                          "Server returned an invalid login session.");
        return;
    }

    // 更新配置
    ConfigurationManager &Config = GlobalConfiguration();
    Config.SetValue("Account", "IsLoggedIn", true);
    Config.SetValue("Account", "UserName", CleanUsername);
    Config.SetValue("Account", "UserType", UserType);
    Config.SetValue("Account", "Title", Title);
    Config.SetValue("Account", "Token", Token);
    Config.SetValue("Account", "LastLoginTime",
                   QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));

    // 更新内存会话
    auto &Ctx = ApplicationContext();
    Ctx.Account.IsLoggedIn = true;
    Ctx.Account.UserName = CleanUsername;
    Ctx.Account.Title = Title;
    Ctx.Account.UserType = UserType;
    Ctx.Account.Token = Token;
    NotifyAccountSessionChanged();

    // 凭证保存
    if (RememberMe) {
        Config.SetValue("Account", "SaveCredentials", true);
        Config.SetValue("Account", "Password", EncryptPassword(Password));
    } else {
        Config.SetValue("Account", "SaveCredentials", false);
        Config.SetValue("Account", "Password", "");
    }
    Config.SetValue("Account", "AutoLogin", AutoLogin);
    Config.SaveConfiguration();

    if (NoticeParent)
        ShowSuccessNotice(NoticeParent, "Account",
                        QString("Welcome, %1!").arg(CleanUsername));
}

bool AuthService::Login(const QString &Username, const QString &Password,
                       bool RememberMe, bool AutoLogin,
                       QWidget *NoticeParent, QString *ErrorMessage) {
    QJsonObject Payload;
    Payload["username"] = Username.trimmed();
    Payload["password"] = Sha256Hex(Password);

    QString Error;
    QJsonObject Response = SendAuthRequest("/api/login", Payload, &Error);

    if (!Error.isEmpty()) {
        if (ErrorMessage)
            *ErrorMessage = Error;
        if (NoticeParent)
            ShowErrorNotice(NoticeParent, "Login Failed", Error);
        return false;
    }

    const int Code = Response["code"].toInt(-1);
    const QString Message = Response["message"].toString();

    if (Code == 0) {
        HandleLoginSuccess(NoticeParent, Response["data"].toObject(),
                         Username, Password, RememberMe, AutoLogin);
        return true;
    }

    if (ErrorMessage)
        *ErrorMessage = Message.isEmpty() ? "Login failed" : Message;
    if (NoticeParent)
        ShowErrorNotice(NoticeParent, "Login Failed", Message);
    return false;
}

void AuthService::Logout() {
    ConfigurationManager &Config = GlobalConfiguration();
    Config.SetValue("Account", "IsLoggedIn", false);
    Config.SetValue("Account", "UserType", 0);
    Config.SetValue("Account", "Token", "");

    auto &Ctx = ApplicationContext();
    Ctx.Account.IsLoggedIn = false;
    Ctx.Account.UserName.clear();
    Ctx.Account.Title.clear();
    Ctx.Account.UserType = 0;
    Ctx.Account.Token.clear();
    NotifyAccountSessionChanged();

    if (!Config.GetValue("Account", "SaveCredentials", false).toBool()) {
        Config.SetValue("Account", "UserName", "");
        Config.SetValue("Account", "Password", "");
    }

    Config.SaveConfiguration();
}

bool AuthService::Register(const QString &Username, const QString &Password,
                          QWidget *NoticeParent, QString *ErrorMessage) {
    QJsonObject Payload;
    Payload["username"] = Username.trimmed();
    Payload["password"] = Sha256Hex(Password);

    QString Error;
    QJsonObject Response = SendAuthRequest("/api/register", Payload, &Error);

    if (!Error.isEmpty()) {
        if (ErrorMessage)
            *ErrorMessage = Error;
        if (NoticeParent)
            ShowErrorNotice(NoticeParent, "Registration Failed", Error);
        return false;
    }

    const int Code = Response["code"].toInt(-1);
    const QString Message = Response["message"].toString();

    if (Code == 0) {
        if (NoticeParent)
            ShowSuccessNotice(NoticeParent, "Registration Successful",
                            "Account created successfully. Please login.");
        return true;
    }

    if (ErrorMessage)
        *ErrorMessage = Message.isEmpty() ? "Registration failed" : Message;
    if (NoticeParent)
        ShowErrorNotice(NoticeParent, "Registration Failed", Message);
    return false;
}

bool AuthService::TryAutoLogin(QWidget *NoticeParent) {
    ConfigurationManager &Config = GlobalConfiguration();

    if (!Config.GetValue("Account", "AutoLogin", false).toBool())
        return false;

    if (!Config.GetValue("Account", "SaveCredentials", false).toBool())
        return false;

    const QString Username = Config.GetValue("Account", "UserName").toString();
    const QString EncryptedPassword = Config.GetValue("Account", "Password").toString();

    if (Username.isEmpty() || EncryptedPassword.isEmpty())
        return false;

    const QString Password = DecryptPassword(EncryptedPassword);
    if (Password.isEmpty())
        return false;

    return Login(Username, Password, true, true, NoticeParent);
}

bool AuthService::IsLoggedIn() const {
    return ApplicationContext().Account.IsLoggedIn;
}

QString AuthService::GetUsername() const {
    return ApplicationContext().Account.UserName;
}

QString AuthService::GetToken() const {
    return ApplicationContext().Account.Token;
}

int AuthService::GetUserType() const {
    return ApplicationContext().Account.UserType;
}

// 全局实例
AuthService &GlobalAuthService() {
    static AuthService Instance;
    return Instance;
}

} // namespace AegisNT
