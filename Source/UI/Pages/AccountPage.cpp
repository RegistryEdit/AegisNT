// ============================================================
// 账号页：登录状态/注册/改密/用户类型管理，
// 会话与凭证逻辑见 Source/Core/Auth/AuthHelpers.inc。
// ============================================================
QWidget *CreateAccountPage() {
  auto *Page = new AegisNT::PageBase(nullptr);
  auto *Layout = Page->GetMainLayout();
  ConfigurePageLayout(Layout, 8);

  // 服务器地址
  QString KServerAddress = AuthServerAddress();

  // 网络管理器
  QNetworkAccessManager *NetworkManager = new QNetworkAccessManager(Page);

  // ========== 状态区 ==========
  auto *StatusLayout = new QVBoxLayout;
  StatusLayout->setContentsMargins(16, 12, 16, 12);
  StatusLayout->setSpacing(8);

  auto *StatusHeaderLayout = new QHBoxLayout;
  auto *StatusTitle =
      MakeLabel("Login Status", 14, KAccent, QFont::DemiBold);
  auto *LogoutButton = MakeButton("Logout");
  LogoutButton->setEnabled(false);
  StatusHeaderLayout->addWidget(StatusTitle);
  StatusHeaderLayout->addStretch();
  StatusHeaderLayout->addWidget(LogoutButton);
  StatusLayout->addLayout(StatusHeaderLayout);

  auto *StatusLabel = MakeLabel("● Not Logged In", 11, KTextMuted);
  auto *UserNameLabel = MakeLabel("User: -", 11, KTextMuted);
  auto *UserTypeLabel = MakeLabel("Type: -", 11, KTextMuted);
  auto *LastLoginLabel = MakeLabel("Last Login: -", 11, KTextMuted);

  StatusLayout->addWidget(StatusLabel);
  StatusLayout->addWidget(UserNameLabel);
  StatusLayout->addWidget(UserTypeLabel);
  StatusLayout->addWidget(LastLoginLabel);

  Layout->addLayout(StatusLayout);

  // 更新状态 UI 的函数

const auto UpdateStatusUI = [=](bool IsLoggedIn, const QString &Username,
                                   int UserType) {
    const auto LocalizedStatusText = [](const QString &Text) {
      return ActiveLanguage == "zh_CN" ? TranslateText(Text) : Text;
    };

    if (IsLoggedIn) {
      StatusLabel->setText(LocalizedStatusText("● Logged In"));
      StatusLabel->setStyleSheet("color: #10B981; font-weight: 600;");
      const QString DisplayName = Account.Title.trimmed().isEmpty()
                                       ? Username
                                       : QString("[%1]%2").arg(Account.Title.trimmed(), Username);
      UserNameLabel->setText(
          LocalizedStatusText("User: %1").arg(DisplayName.isEmpty() ? "-" : DisplayName));
      switch (UserType) {
      case 0:
        UserTypeLabel->setText(LocalizedStatusText("Type: Regular User"));
        break;
      case 1:
        UserTypeLabel->setText(LocalizedStatusText("Type: Administrator"));
        break;
      default:
        UserTypeLabel->setText(
            LocalizedStatusText("Type: Unknown (%1)").arg(UserType));
        break;
      }
      QString LastLogin = ConfigurationValue("Account", "LastLoginTime", "-")
                              .toString();
      LastLoginLabel->setText(
          LocalizedStatusText("Last Login: %1").arg(LastLogin));
    } else {
      StatusLabel->setText(LocalizedStatusText("● Not Logged In"));
      StatusLabel->setStyleSheet("color: #EF4444; font-weight: 600;");
      UserNameLabel->setText(LocalizedStatusText("User: %1").arg("-"));
      UserTypeLabel->setText(LocalizedStatusText("Type: -"));
      LastLoginLabel->setText(LocalizedStatusText("Last Login: %1").arg("-"));
    }
  };

  // 登录已移至启动时的 Login Dialog(以及登出后的重新弹出)。

  const auto RefreshUserType = [=]() {
    if (!Account.IsLoggedIn)
      return;
    const QString Token = Account.Token;
    if (Token.isEmpty())
      return;

    QNetworkRequest Request(QUrl(KServerAddress + "/QueryUserType"));
    Request.setRawHeader("Authorization", ("Bearer " + Token).toUtf8());
    Request.setTransferTimeout(4000);
    QNetworkReply *Reply = NetworkManager->get(Request);
    QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
      const bool SameLoginSession =
          Account.IsLoggedIn && Account.Token == Token;
      if (SameLoginSession && Reply->error() == QNetworkReply::NoError) {
        const QJsonObject Response =
            QJsonDocument::fromJson(Reply->readAll()).object();
        if (Response["success"].toBool()) {
          const QJsonObject Data = Response["data"].toObject();
          const QString Username = Data["UserName"].toString();
          const QString Title = Data["Title"].toString();
          const int UserType = Data["UserType"].toInt(-1);
          if (!Username.isEmpty() && UserType >= 0) {
            if (ConfigurationValue("Account", "UserName", "").toString() !=
                Username)
              SetConfigurationValue("Account", "UserName", Username);
            if (ConfigurationValue("Account", "UserType", -1).toInt() !=
                UserType)
              SetConfigurationValue("Account", "UserType", UserType);
            if (ConfigurationValue("Account", "Title", "").toString() !=
                Title)
              SetConfigurationValue("Account", "Title", Title);
            Account.UserName = Username;
            Account.Title = Title;
            Account.UserType = UserType;
            AegisNT::NotifyAccountSessionChanged();
            UpdateStatusUI(true, Username, UserType);
          }
        }
      }
      Reply->deleteLater();
    });
  };

  // 登录/登出会话逻辑已提取至 Source/Core/Auth/AuthHelpers.inc,由启动登录
  // 流程(LoginDialog)与 AccountSessionListeners 驱动页面状态刷新。

  // 退出登录:清空会话后立即弹出 Login Dialog(不再走静默自动登录,
  // 否则保存的凭证会让这次登出毫无效果);用户关闭登录框则退出程序。
  const auto HandleLogoutClicked = [=]() {
    HandleLogout();
    if (!RunLoginFlow(Page, {}, /*AllowAutoLogin=*/false)) {
      QCoreApplication::quit();
    }
  };

  QObject::connect(LogoutButton, &QPushButton::clicked, Page,
                   HandleLogoutClicked);

  // 会话状态刷新：状态标签、Logout 可用性与管理员面板都由当前会话决定。
  // 页面是按需懒加载的，多数情况下创建时登录早已完成且不会再有会话通知，
  // 因此初始化时也要主动执行一次，否则 Logout 会一直停在创建时的禁用态。
  const QPointer<QWidget> StatusPageGuard(Page);
  auto LastListenerUser = std::make_shared<QString>();
  const auto RefreshSessionState = [=]() -> bool {
    if (!StatusPageGuard)
      return false;
    UpdateStatusUI(Account.IsLoggedIn, Account.UserName, Account.UserType);
    LogoutButton->setEnabled(Account.IsLoggedIn);
    // 会话用户变化时(登录/重新登录)向服务器核对最新的用户类型与 Title;
    // 以用户名去重,避免 RefreshUserType 内部再次通知造成循环刷新。
    if (Account.IsLoggedIn && !Account.Token.isEmpty() &&
        *LastListenerUser != Account.UserName) {
      *LastListenerUser = Account.UserName;
      RefreshUserType();
    }
    if (!Account.IsLoggedIn)
      LastListenerUser->clear();
    return true;
  };
  AegisNT::ApplicationContext().AccountSessionListeners.push_back(
      RefreshSessionState);

  // ========== 注册区 ==========
  auto *RegisterLayout = new QVBoxLayout;
  RegisterLayout->setContentsMargins(16, 12, 16, 12);
  RegisterLayout->setSpacing(12);

  auto *RegisterTitle = MakeLabel("Register", 14, KAccent, QFont::DemiBold);
  RegisterLayout->addWidget(RegisterTitle);

  auto *RegisterUsernameEdit = new LineEdit;
  RegisterUsernameEdit->setPlaceholderText("Username");
  RegisterLayout->addWidget(RegisterUsernameEdit);

  auto *RegisterPasswordEdit = new LineEdit;
  RegisterPasswordEdit->setPlaceholderText("Password");
  RegisterPasswordEdit->setEchoMode(QLineEdit::Password);
  RegisterLayout->addWidget(RegisterPasswordEdit);

  auto *RegisterStatusLayout = new QHBoxLayout;
  auto *RegisterLoadingRing = new IndeterminateProgressRing;
  RegisterLoadingRing->setFixedSize(24, 24);
  RegisterLoadingRing->setVisible(false);

  auto *RegisterErrorLabel = MakeLabel("", 10, KTextMuted);
  RegisterErrorLabel->setVisible(false);

  RegisterStatusLayout->addWidget(RegisterLoadingRing);
  RegisterStatusLayout->addWidget(RegisterErrorLabel, 1);
  RegisterLayout->addLayout(RegisterStatusLayout);

  auto *RegisterButtonLayout = new QHBoxLayout;
  auto *RegisterButton = MakeButton("Register", true);
  RegisterButtonLayout->addStretch();
  RegisterButtonLayout->addWidget(RegisterButton);
  RegisterLayout->addLayout(RegisterButtonLayout);

  Layout->addLayout(RegisterLayout);

  const auto ShowRegisterError = [=](const QString &Message) {
    AppendConsoleOutput("[!] Account registration: " + Message + "\n");
    RegisterErrorLabel->setText("Error: " + Message);
    RegisterErrorLabel->setStyleSheet("color: #EF4444;");
    RegisterErrorLabel->setVisible(true);
    QTimer::singleShot(5000, [RegisterErrorLabel]() {
      RegisterErrorLabel->setVisible(false);
    });
  };

  const auto SendRegisterRequest = [=]() {
    QString Username = RegisterUsernameEdit->text().trimmed();
    QString Password = RegisterPasswordEdit->text();

    if (Username.isEmpty() || Password.isEmpty()) {
      ShowRegisterError("Username and password cannot be empty");
      return;
    }

    if (Password.length() < 6) {
      ShowRegisterError("Password must be at least 6 characters");
      return;
    }

    QNetworkRequest Request(QUrl(KServerAddress + "/Register"));
    Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject Json;
    Json["UserName"] = Username;
    Json["Password"] = Sha256Hex(Password);  // 发送 SHA-256 哈希
    // 不提交 UserType 字段 —— 服务器会强制新账号为普通用户(0)。

    QByteArray Data = QJsonDocument(Json).toJson();

    RegisterLoadingRing->setVisible(true);
    RegisterErrorLabel->setVisible(false);
    RegisterButton->setEnabled(false);

    QNetworkReply *Reply = NetworkManager->post(Request, Data);

    QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
      RegisterLoadingRing->setVisible(false);
      RegisterButton->setEnabled(true);

      if (Reply->error() == QNetworkReply::NoError) {
        QJsonDocument Doc = QJsonDocument::fromJson(Reply->readAll());
        QJsonObject Response = Doc.object();

        if (Response["success"].toBool()) {
          ShowSuccessNotice(
              Page, "Account",
              QString("User '%1' registered successfully!").arg(Username));
          RegisterUsernameEdit->clear();
          RegisterPasswordEdit->clear();
        } else {
          ShowRegisterError(Response["message"].toString());
        }
      } else {
        ShowRegisterError("Network error: " + Reply->errorString());
      }

      Reply->deleteLater();
    });
  };

  QObject::connect(RegisterButton, &QPushButton::clicked, Page,
                   SendRegisterRequest);
  QObject::connect(RegisterPasswordEdit, &QLineEdit::returnPressed, Page,
                   SendRegisterRequest);

  // ========== 修改密码区 ==========
  auto *ChangePasswordLayout = new QVBoxLayout;
  ChangePasswordLayout->setContentsMargins(16, 12, 16, 12);
  ChangePasswordLayout->setSpacing(12);

  auto *ChangePasswordTitle =
      MakeLabel("Change Password", 14, KAccent, QFont::DemiBold);
  ChangePasswordLayout->addWidget(ChangePasswordTitle);

  auto *CPUsernameEdit = new LineEdit;
  CPUsernameEdit->setPlaceholderText("Username");
  ChangePasswordLayout->addWidget(CPUsernameEdit);

  auto *CPOldPasswordEdit = new LineEdit;
  CPOldPasswordEdit->setPlaceholderText("Old Password");
  CPOldPasswordEdit->setEchoMode(QLineEdit::Password);
  ChangePasswordLayout->addWidget(CPOldPasswordEdit);

  auto *CPNewPasswordEdit = new LineEdit;
  CPNewPasswordEdit->setPlaceholderText("New Password");
  CPNewPasswordEdit->setEchoMode(QLineEdit::Password);
  ChangePasswordLayout->addWidget(CPNewPasswordEdit);

  auto *CPStatusLayout = new QHBoxLayout;
  auto *CPLoadingRing = new IndeterminateProgressRing;
  CPLoadingRing->setFixedSize(24, 24);
  CPLoadingRing->setVisible(false);

  auto *CPErrorLabel = MakeLabel("", 10, KTextMuted);
  CPErrorLabel->setVisible(false);

  CPStatusLayout->addWidget(CPLoadingRing);
  CPStatusLayout->addWidget(CPErrorLabel, 1);
  ChangePasswordLayout->addLayout(CPStatusLayout);

  auto *CPButtonLayout = new QHBoxLayout;
  auto *ChangePasswordButton = MakeButton("Change Password", true);
  CPButtonLayout->addStretch();
  CPButtonLayout->addWidget(ChangePasswordButton);
  ChangePasswordLayout->addLayout(CPButtonLayout);

  Layout->addLayout(ChangePasswordLayout);

  const auto ShowCPError = [=](const QString &Message) {
    AppendConsoleOutput("[!] Change password: " + Message + "\n");
    CPErrorLabel->setText("Error: " + Message);
    CPErrorLabel->setStyleSheet("color: #EF4444;");
    CPErrorLabel->setVisible(true);
    QTimer::singleShot(5000,
                       [CPErrorLabel]() { CPErrorLabel->setVisible(false); });
  };

  const auto SendChangePasswordRequest = [=]() {
    QString Username = CPUsernameEdit->text().trimmed();
    QString OldPassword = CPOldPasswordEdit->text();
    QString NewPassword = CPNewPasswordEdit->text();

    if (Username.isEmpty() || OldPassword.isEmpty() || NewPassword.isEmpty()) {
      ShowCPError("All fields are required");
      return;
    }

    if (NewPassword.length() < 6) {
      ShowCPError("New password must be at least 6 characters");
      return;
    }

    QNetworkRequest Request(QUrl(KServerAddress + "/ChangePassword"));
    Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject Json;
    Json["UserName"] = Username;
    Json["OldPassword"] = Sha256Hex(OldPassword);  // Send SHA-256 hash
    Json["NewPassword"] = Sha256Hex(NewPassword);  // Send SHA-256 hash

    QByteArray Data = QJsonDocument(Json).toJson();

    CPLoadingRing->setVisible(true);
    CPErrorLabel->setVisible(false);
    ChangePasswordButton->setEnabled(false);

    QNetworkReply *Reply = NetworkManager->post(Request, Data);

    QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
      CPLoadingRing->setVisible(false);
      ChangePasswordButton->setEnabled(true);

      if (Reply->error() == QNetworkReply::NoError) {
        QJsonDocument Doc = QJsonDocument::fromJson(Reply->readAll());
        QJsonObject Response = Doc.object();

        if (Response["success"].toBool()) {
          ShowSuccessNotice(
              Page, "Account",
              QString("Password changed successfully for '%1'!").arg(Username));
          CPUsernameEdit->clear();
          CPOldPasswordEdit->clear();
          CPNewPasswordEdit->clear();

          // 如果是当前登录用户修改密码，更新保存的凭证

QString CurrentUser =
              ConfigurationValue("Account", "UserName", "").toString();
          if (Username == CurrentUser &&
              ConfigurationValue("Account", "SaveCredentials", false)
                  .toBool()) {
            SetConfigurationValue("Account", "Password",
                                  EncryptPassword(NewPassword));
          }
        } else {
          ShowCPError(Response["message"].toString());
        }
      } else {
        ShowCPError("Network error: " + Reply->errorString());
      }

      Reply->deleteLater();
    });
  };

  QObject::connect(ChangePasswordButton, &QPushButton::clicked, Page,
                   SendChangePasswordRequest);
  QObject::connect(CPNewPasswordEdit, &QLineEdit::returnPressed, Page,
                   SendChangePasswordRequest);

  // ========== 修改用户类型区 ==========
  auto *AdminPanel = new QWidget;
  auto *ChangeUserTypeLayout = new QVBoxLayout;
  ChangeUserTypeLayout->setContentsMargins(16, 12, 16, 12);
  ChangeUserTypeLayout->setSpacing(12);

  auto *ChangeUserTypeTitle =
      MakeLabel("Change User Type (Admin Only)", 14, KAccent, QFont::DemiBold);
  ChangeUserTypeLayout->addWidget(ChangeUserTypeTitle);

  auto *AdminNameEdit = new LineEdit;
  AdminNameEdit->setPlaceholderText("Admin Username");
  ChangeUserTypeLayout->addWidget(AdminNameEdit);

  auto *AdminPasswordEdit = new LineEdit;
  AdminPasswordEdit->setPlaceholderText("Admin Password");
  AdminPasswordEdit->setEchoMode(QLineEdit::Password);
  ChangeUserTypeLayout->addWidget(AdminPasswordEdit);

  auto *TargetUserEdit = new LineEdit;
  TargetUserEdit->setPlaceholderText("Target Username");
  ChangeUserTypeLayout->addWidget(TargetUserEdit);

  auto *NewUserTypeCombo = new ComboBox;
  NewUserTypeCombo->addItems({"Regular User", "Administrator"});
  NewUserTypeCombo->setItemData(0, 0, Qt::UserRole);
  NewUserTypeCombo->setItemData(1, 1, Qt::UserRole);
  ChangeUserTypeLayout->addWidget(NewUserTypeCombo);
  auto *NewUserTitleEdit = new LineEdit;
  NewUserTitleEdit->setPlaceholderText("Title (optional, max 48 characters)");
  ChangeUserTypeLayout->addWidget(NewUserTitleEdit);

  auto *CUTStatusLayout = new QHBoxLayout;
  auto *CUTLoadingRing = new IndeterminateProgressRing;
  CUTLoadingRing->setFixedSize(24, 24);
  CUTLoadingRing->setVisible(false);

  auto *CUTErrorLabel = MakeLabel("", 10, KTextMuted);
  CUTErrorLabel->setVisible(false);

  CUTStatusLayout->addWidget(CUTLoadingRing);
  CUTStatusLayout->addWidget(CUTErrorLabel, 1);
  ChangeUserTypeLayout->addLayout(CUTStatusLayout);

  auto *CUTButtonLayout = new QHBoxLayout;
  auto *ChangeUserTypeButton = MakeButton("Change User Type", true);
  CUTButtonLayout->addStretch();
  CUTButtonLayout->addWidget(ChangeUserTypeButton);
  ChangeUserTypeLayout->addLayout(CUTButtonLayout);

  AdminPanel->setLayout(ChangeUserTypeLayout);
  AdminPanel->setVisible(false);
  Layout->addWidget(AdminPanel);
  const QPointer<QWidget> AdminPanelGuard(AdminPanel);
  AegisNT::ApplicationContext().AccountSessionListeners.push_back(
      [AdminPanelGuard]() -> bool {
        if (!AdminPanelGuard)
          return false;
        AdminPanelGuard->setVisible(Account.IsLoggedIn && Account.UserType == 1);
        return true;
      });

  const auto ShowCUTError = [=](const QString &Message) {
    AppendConsoleOutput("[!] Change user type: " + Message + "\n");
    CUTErrorLabel->setText("Error: " + Message);
    CUTErrorLabel->setStyleSheet("color: #EF4444;");
    CUTErrorLabel->setVisible(true);
    QTimer::singleShot(5000, [CUTErrorLabel]() {
      CUTErrorLabel->setVisible(false);
    });
  };

  const auto SendChangeUserTypeRequest = [=]() {
    QString AdminName = AdminNameEdit->text().trimmed();
    QString AdminPassword = AdminPasswordEdit->text();
    QString TargetUser = TargetUserEdit->text().trimmed();
    int NewUserType = NewUserTypeCombo->currentData(Qt::UserRole).toInt();

    if (AdminName.isEmpty() || AdminPassword.isEmpty() ||
        TargetUser.isEmpty()) {
      ShowCUTError("All fields are required");
      return;
    }

    QNetworkRequest Request(QUrl(KServerAddress + "/ChangeUserType"));
    Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject Json;
    Json["AdminName"] = AdminName;
    Json["AdminPassword"] = Sha256Hex(AdminPassword);  // Send SHA-256 hash
    Json["TargetUserName"] = TargetUser;
    Json["NewUserType"] = NewUserType;
    Json["Title"] = NewUserTitleEdit->text().trimmed();

    QByteArray Data = QJsonDocument(Json).toJson();

    CUTLoadingRing->setVisible(true);
    CUTErrorLabel->setVisible(false);
    ChangeUserTypeButton->setEnabled(false);

    QNetworkReply *Reply = NetworkManager->post(Request, Data);

    QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
      CUTLoadingRing->setVisible(false);
      ChangeUserTypeButton->setEnabled(true);

      if (Reply->error() == QNetworkReply::NoError) {
        QJsonDocument Doc = QJsonDocument::fromJson(Reply->readAll());
        QJsonObject Response = Doc.object();

        if (Response["success"].toBool()) {
          QString TypeName =
              (NewUserType == 1) ? "Administrator" : "Regular User";
          const QString NewTitle = NewUserTitleEdit->text().trimmed();
          AegisNT::NotifyUserTitleChanged(TargetUser, NewTitle);
          ShowSuccessNotice(
              Page, "Account",
              QString("User '%1' changed to %2!").arg(TargetUser, TypeName));
          AdminNameEdit->clear();
          AdminPasswordEdit->clear();
          TargetUserEdit->clear();
          NewUserTypeCombo->setCurrentIndex(0);

          // 如果修改的是当前登录用户，更新状态

QString CurrentUser =
              ConfigurationValue("Account", "UserName", "").toString();
          if (TargetUser == CurrentUser) {
            SetConfigurationValue("Account", "UserType", NewUserType);
            SetConfigurationValue("Account", "Title", NewTitle);
            Account.UserName = CurrentUser;
            Account.UserType = NewUserType;
            Account.Title = NewTitle;
            AegisNT::NotifyAccountSessionChanged();
            bool IsLoggedIn =
                ConfigurationValue("Account", "IsLoggedIn", false).toBool();
            if (IsLoggedIn) {
              UpdateStatusUI(true, CurrentUser, NewUserType);
            }
          }
        } else {
          ShowCUTError(Response["message"].toString());
        }
      } else {
        ShowCUTError("Network error: " + Reply->errorString());
      }

      Reply->deleteLater();
    });
  };

  QObject::connect(ChangeUserTypeButton, &QPushButton::clicked, Page,
                   SendChangeUserTypeRequest);

  // ========== 初始化:会话由启动时的 Login Dialog / 自动登录建立 ==========
  RefreshSessionState();
  AdminPanel->setVisible(Account.IsLoggedIn && Account.UserType == 1);

  // 包装到滚动区域

auto *Scroll = new ScrollArea;
  Scroll->setWidget(Page);
  Scroll->setWidgetResizable(true);

  return WrapPage(Scroll);
}
