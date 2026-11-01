// 共享的账号认证逻辑:SHA-256/凭证混淆、登录/登出会话持久化、JSON HTTP 请求封装。
// 以 .inc 形式并入 AegisNT.cpp,依赖其顶部 Qt 头文件、Account 别名、
// ConfigurationValue/SetConfigurationValue、Show*Notice 等 UI 辅助函数。

static QString Sha256Hex(const QString &Input) {
  return QString(QCryptographicHash::hash(Input.toUtf8(),
                                          QCryptographicHash::Sha256)
                     .toHex());
}

// 凭证保护:DPAPI(CryptProtectData)按当前用户加密,旧版 XOR+Base64 仅作
// 兼容读取,解密成功后由调用方以新格式回写。
#include <wincrypt.h>

static QString EncryptPassword(const QString &Password) {
  const QByteArray Raw = Password.toUtf8();
  DATA_BLOB In, Out;
  In.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(Raw.constData()));
  In.cbData = static_cast<DWORD>(Raw.size());
  if (!CryptProtectData(&In, L"AegisNT.Password", nullptr, nullptr, nullptr, 0,
                        &Out))
    return QString();
  const QByteArray Blob(reinterpret_cast<const char *>(Out.pbData),
                        static_cast<int>(Out.cbData));
  LocalFree(Out.pbData);
  return QLatin1String("DPAPI:") + QString(Blob.toBase64());
}

static QString DecryptPassword(const QString &Encrypted) {
  if (Encrypted.startsWith(QLatin1String("DPAPI:"))) {
    const QByteArray Blob =
        QByteArray::fromBase64(Encrypted.mid(6).toUtf8());
    DATA_BLOB In, Out;
    In.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(Blob.constData()));
    In.cbData = static_cast<DWORD>(Blob.size());
    if (!CryptUnprotectData(&In, nullptr, nullptr, nullptr, nullptr, 0, &Out))
      return QString();
    const QString Plain = QString::fromUtf8(
        reinterpret_cast<const char *>(Out.pbData), static_cast<int>(Out.cbData));
    LocalFree(Out.pbData);
    return Plain;
  }
  // 旧格式:单字节 XOR + Base64,非安全加密,仅为兼容历史配置保留。
  QByteArray Data = QByteArray::fromBase64(Encrypted.toUtf8());
  const char Key = 0xAA;
  for (int I = 0; I < Data.size(); ++I)
    Data[I] = Data[I] ^ Key;
  return QString(Data);
}

static QString AuthServerAddress() {
  QString Address =
      ConfigurationValue("LicenseServer", "Address", "http://localhost:8888")
          .toString()
          .trimmed();
  while (Address.endsWith('/'))
    Address.chop(1);
  if (Address.isEmpty())
    Address = "http://localhost:8888";
  return Address;
}

// 登出:清空内存会话,并删除本机保存的全部凭证(记住的密码、Remember Me /
// Auto Login 标记)。保留用户名仅用于登录框预填——它不是凭证,也不会让
// 程序在未验证的情况下恢复登录态。

static void HandleLogout() {
  SetConfigurationValue("Account", "IsLoggedIn", false);
  SetConfigurationValue("Account", "UserType", 0);
  SetConfigurationValue("Account", "Token", "");
  SetConfigurationValue("Account", "Title", "");
  // 凭证与自动登录标记:登出后必须重新输入密码,否则下次启动(以及登出后
  // 点击 Skip)会被保存的凭证重新认证回登录态。
  SetConfigurationValue("Account", "Password", "");
  SetConfigurationValue("Account", "PasswordMD5", "");
  SetConfigurationValue("Account", "SaveCredentials", false);
  SetConfigurationValue("Account", "AutoLogin", false);
  Account.IsLoggedIn = false;
  Account.UserName.clear();
  Account.Title.clear();
  Account.UserType = 0;
  Account.Token.clear();
  AegisNT::NotifyAccountSessionChanged();
}

// 登录成功:校验服务器返回的 data,写入内存会话并持久化
// Token / LastLoginTime / Remember Me 凭证 / Auto Login 标记。

static void HandleLoginSuccess(QWidget *NoticeParent, const QJsonObject &Data,
                               const QString &Username, const QString &Password,
                               bool RememberMe, bool AutoLogin) {
  const QString CleanUsername = Username.trimmed();
  const QString Title = Data["Title"].toString();
  const int UserType = Data["UserType"].toInt(-1);
  const QString Token = Data["Token"].toString().trimmed();
  if (CleanUsername.isEmpty() || Token.isEmpty() ||
      (UserType != 0 && UserType != 1)) {
    Account = {};
    SetConfigurationValue("Account", "IsLoggedIn", false);
    SetConfigurationValue("Account", "Token", "");
    if (NoticeParent)
      ShowErrorNotice(NoticeParent, "Account",
                      "Server returned an invalid login session.");
    AegisNT::NotifyAccountSessionChanged();
    return;
  }

  SetConfigurationValue("Account", "IsLoggedIn", true);
  SetConfigurationValue("Account", "UserName", CleanUsername);
  SetConfigurationValue("Account", "UserType", UserType);
  SetConfigurationValue("Account", "Title", Title);
  SetConfigurationValue("Account", "Token", Token);
  Account.IsLoggedIn = true;
  Account.UserName = CleanUsername;
  Account.Title = Title;
  Account.UserType = UserType;
  Account.Token = Token;
  AegisNT::NotifyAccountSessionChanged();
  SetConfigurationValue("Account", "LastLoginTime",
                        QDateTime::currentDateTime().toString(
                            "yyyy-MM-dd HH:mm:ss"));

  if (RememberMe) {
    SetConfigurationValue("Account", "SaveCredentials", true);
    SetConfigurationValue("Account", "Password", EncryptPassword(Password));
  } else {
    SetConfigurationValue("Account", "SaveCredentials", false);
    SetConfigurationValue("Account", "Password", "");
  }
  SetConfigurationValue("Account", "AutoLogin", AutoLogin);

  if (NoticeParent)
    ShowSuccessNotice(NoticeParent, "Account",
                      QString("Welcome, %1!").arg(CleanUsername));
}

// 异步 POST JSON:Callback 在 finished 信号中触发;Error 非空表示网络层失败。

static void PostJsonRequest(
    const QString &Path, const QJsonObject &Body, QObject *Lifetime,
    const std::function<void(const QJsonObject &, const QString &)>
        &Callback) {
  auto *Manager = new QNetworkAccessManager(Lifetime);
  QNetworkRequest Request(QUrl(AuthServerAddress() + Path));
  Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  Request.setTransferTimeout(6000);
  QNetworkReply *Reply = Manager->post(Request, QJsonDocument(Body).toJson());
  QObject::connect(Reply, &QNetworkReply::finished, Lifetime, [=]() {
    QString Error;
    QJsonObject Response;
    if (Reply->error() == QNetworkReply::NoError)
      Response = QJsonDocument::fromJson(Reply->readAll()).object();
    else
      Error = Reply->errorString();
    Callback(Response, Error);
    Reply->deleteLater();
    Manager->deleteLater();
  });
}

// 阻塞式 POST JSON(QEventLoop 等待),用于主窗口创建前的静默自动登录。

static bool PostJsonRequestBlocking(const QString &Path,
                                    const QJsonObject &Body, int TimeoutMs,
                                    QJsonObject *Response, QString *Error) {
  QNetworkAccessManager Manager;
  QNetworkRequest Request(QUrl(AuthServerAddress() + Path));
  Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  Request.setTransferTimeout(TimeoutMs);
  QNetworkReply *Reply = Manager.post(Request, QJsonDocument(Body).toJson());
  QEventLoop Loop;
  QObject::connect(Reply, &QNetworkReply::finished, &Loop, &QEventLoop::quit);
  Loop.exec();
  const bool Ok = Reply->error() == QNetworkReply::NoError;
  if (Ok)
    *Response = QJsonDocument::fromJson(Reply->readAll()).object();
  else
    *Error = Reply->errorString();
  Reply->deleteLater();
  return Ok;
}
