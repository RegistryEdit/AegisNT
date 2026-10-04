#pragma once

#include <QJsonObject>
#include <QString>
#include <QWidget>

namespace AegisNT {

/**
 * AuthService - 认证服务
 *
 * 职责：
 * - 用户登录/登出/注册
 * - 凭证加密存储（DPAPI）
 * - Token 管理
 * - 与 LicenseServer 通信
 */
class AuthService {
public:
    AuthService();
    ~AuthService();

    // 密码处理
    static QString Sha256Hex(const QString &Input);
    static QString EncryptPassword(const QString &Password);
    static QString DecryptPassword(const QString &Encrypted);

    // 认证服务器地址
    QString GetAuthServerAddress() const;

    // 登录/登出
    bool Login(const QString &Username, const QString &Password,
              bool RememberMe, bool AutoLogin,
              QWidget *NoticeParent, QString *ErrorMessage = nullptr);

    void Logout();

    bool Register(const QString &Username, const QString &Password,
                 QWidget *NoticeParent, QString *ErrorMessage = nullptr);

    // 自动登录
    bool TryAutoLogin(QWidget *NoticeParent);

    // 会话管理
    bool IsLoggedIn() const;
    QString GetUsername() const;
    QString GetToken() const;
    int GetUserType() const;

private:
    // HTTP 请求辅助
    QJsonObject SendAuthRequest(const QString &Endpoint,
                               const QJsonObject &Payload,
                               QString *ErrorMessage = nullptr);

    void HandleLoginSuccess(QWidget *NoticeParent, const QJsonObject &Data,
                          const QString &Username, const QString &Password,
                          bool RememberMe, bool AutoLogin);
};

// 全局实例
AuthService &GlobalAuthService();

} // namespace AegisNT
