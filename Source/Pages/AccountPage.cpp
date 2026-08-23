QWidget *CreateAccountPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout, 8);

  // 服务器地址常量
  const QString KServerAddress = "http://localhost:8888";

  // 网络管理器
  QNetworkAccessManager *NetworkManager = new QNetworkAccessManager(Page);

  // SHA-256 计算函数（用于传输层保护）
  const auto CalculateSHA256 = [](const QString &Input) -> QString {
    QByteArray Hash =
        QCryptographicHash::hash(Input.toUtf8(), QCryptographicHash::Sha256);
    return QString(Hash.toHex());
  };

  // 凭证加密/解密函数（简单 XOR + Base64）
  const auto EncryptPassword = [](const QString &Password) -> QString {
    QByteArray Data = Password.toUtf8();
    const char Key = 0xAA;
    for (int I = 0; I < Data.size(); ++I) {
      Data[I] = Data[I] ^ Key;
    }
    return QString(Data.toBase64());
  };

  const auto DecryptPassword = [](const QString &Encrypted) -> QString {
    QByteArray Data = QByteArray::fromBase64(Encrypted.toUtf8());
    const char Key = 0xAA;
    for (int I = 0; I < Data.size(); ++I) {
      Data[I] = Data[I] ^ Key;
    }
    return QString(Data);
  };

  // ========== Status Section ==========
  auto *StatusLayout = new QVBoxLayout;
  StatusLayout->setContentsMargins(16, 12, 16, 12);
  StatusLayout->setSpacing(8);

  auto *StatusTitle =
      MakeLabel("Login Status", 14, KAccent, QFont::DemiBold);
  StatusLayout->addWidget(StatusTitle);

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
    if (IsLoggedIn) {
      StatusLabel->setText("● Logged In");
      StatusLabel->setStyleSheet("color: #10B981; font-weight: 600;");
      UserNameLabel->setText("User: " + Username);
      UserTypeLabel->setText(UserType == 1 ? "Type: Administrator"
                                            : "Type: Regular User");
      QString LastLogin = ConfigurationValue("Account", "LastLoginTime", "-")
                              .toString();
      LastLoginLabel->setText("Last Login: " + LastLogin);
    } else {
      StatusLabel->setText("● Not Logged In");
      StatusLabel->setStyleSheet("color: #EF4444; font-weight: 600;");
      UserNameLabel->setText("User: -");
      UserTypeLabel->setText("Type: -");
      LastLoginLabel->setText("Last Login: -");
    }
  };

  // ========== Login Section ==========
  auto *LoginLayout = new QVBoxLayout;
  LoginLayout->setContentsMargins(16, 12, 16, 12);
  LoginLayout->setSpacing(12);

  auto *LoginTitle = MakeLabel("Login", 14, KAccent, QFont::DemiBold);
  LoginLayout->addWidget(LoginTitle);

  auto *LoginUsernameEdit = new LineEdit;
  LoginUsernameEdit->setPlaceholderText("Username");
  LoginLayout->addWidget(LoginUsernameEdit);

  auto *LoginPasswordEdit = new LineEdit;
  LoginPasswordEdit->setPlaceholderText("Password");
  LoginPasswordEdit->setEchoMode(QLineEdit::Password);
  LoginLayout->addWidget(LoginPasswordEdit);

  auto *LoginOptionsLayout = new QHBoxLayout;
  auto *RememberMeCheckbox = new CheckBox;
  RememberMeCheckbox->setText("Remember Me");
  RememberMeCheckbox->setChecked(
      ConfigurationValue("Account", "SaveCredentials", false).toBool());

  auto *AutoLoginCheckbox = new CheckBox;
  AutoLoginCheckbox->setText("Auto Login");
  AutoLoginCheckbox->setChecked(
      ConfigurationValue("Account", "AutoLogin", false).toBool());

  LoginOptionsLayout->addWidget(RememberMeCheckbox);
  LoginOptionsLayout->addWidget(AutoLoginCheckbox);
  LoginOptionsLayout->addStretch();
  LoginLayout->addLayout(LoginOptionsLayout);

  auto *LoginStatusLayout = new QHBoxLayout;
  auto *LoginLoadingRing = new IndeterminateProgressRing;
  LoginLoadingRing->setFixedSize(24, 24);
  LoginLoadingRing->setVisible(false);

  auto *LoginErrorLabel = MakeLabel("", 10, KTextMuted);
  LoginErrorLabel->setVisible(false);

  LoginStatusLayout->addWidget(LoginLoadingRing);
  LoginStatusLayout->addWidget(LoginErrorLabel, 1);
  LoginLayout->addLayout(LoginStatusLayout);

  auto *LoginButtonLayout = new QHBoxLayout;
  auto *LoginButton = MakeButton("Login", true);
  auto *LogoutButton = MakeButton("Logout");
  LogoutButton->setEnabled(false);

  LoginButtonLayout->addStretch();
  LoginButtonLayout->addWidget(LoginButton);
  LoginButtonLayout->addWidget(LogoutButton);
  LoginLayout->addLayout(LoginButtonLayout);

  Layout->addLayout(LoginLayout);

  // 显示/隐藏登录错误信息
  const auto ShowLoginError = [=](const QString &Message) {
    LoginErrorLabel->setText("Error: " + Message);
    LoginErrorLabel->setStyleSheet("color: #EF4444;");
    LoginErrorLabel->setVisible(true);
    QTimer::singleShot(5000, [LoginErrorLabel]() {
      LoginErrorLabel->setVisible(false);
    });
  };

  // 登录成功处理
  const auto HandleLoginSuccess = [=](const QJsonObject &Data) {
    QString Username = Data["UserName"].toString();
    int UserType = Data["UserType"].toInt();
    QString Token = Data["Token"].toString();

    SetConfigurationValue("Account", "IsLoggedIn", true);
    SetConfigurationValue("Account", "UserName", Username);
    SetConfigurationValue("Account", "UserType", UserType);
    SetConfigurationValue("Account", "Token", Token);
    SetConfigurationValue(
        "Account", "LastLoginTime",
        QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));

    if (RememberMeCheckbox->isChecked()) {
      SetConfigurationValue("Account", "SaveCredentials", true);
      QString Password = LoginPasswordEdit->text();
      SetConfigurationValue("Account", "Password",
                            EncryptPassword(Password));
    } else {
      SetConfigurationValue("Account", "SaveCredentials", false);
      SetConfigurationValue("Account", "Password", "");
    }

    SetConfigurationValue("Account", "AutoLogin",
                          AutoLoginCheckbox->isChecked());

    UpdateStatusUI(true, Username, UserType);
    ShowSuccessNotice(Page, "Account",
                      QString("Welcome, %1!").arg(Username));

    LoginPasswordEdit->clear();
    LoginButton->setEnabled(false);
    LogoutButton->setEnabled(true);
  };

  // 登录请求
  const auto SendLoginRequest = [=]() {
    QString Username = LoginUsernameEdit->text().trimmed();
    QString Password = LoginPasswordEdit->text();

    if (Username.isEmpty() || Password.isEmpty()) {
      ShowLoginError("Username and password cannot be empty");
      return;
    }

    QNetworkRequest Request(QUrl(KServerAddress + "/Login"));
    Request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject Json;
    Json["UserName"] = Username;
    Json["Password"] = CalculateSHA256(Password);  // Send SHA-256 hash

    QByteArray Data = QJsonDocument(Json).toJson();

    LoginLoadingRing->setVisible(true);
    LoginErrorLabel->setVisible(false);
    LoginButton->setEnabled(false);

    QNetworkReply *Reply = NetworkManager->post(Request, Data);

    QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
      LoginLoadingRing->setVisible(false);
      LoginButton->setEnabled(true);

      if (Reply->error() == QNetworkReply::NoError) {
        QJsonDocument Doc = QJsonDocument::fromJson(Reply->readAll());
        QJsonObject Response = Doc.object();

        if (Response["success"].toBool()) {
          HandleLoginSuccess(Response["data"].toObject());
        } else {
          ShowLoginError(Response["message"].toString());
        }
      } else {
        ShowLoginError("Network error: " + Reply->errorString());
      }

      Reply->deleteLater();
    });
  };

  // 退出登录
  const auto HandleLogout = [=]() {
    SetConfigurationValue("Account", "IsLoggedIn", false);

    if (!RememberMeCheckbox->isChecked()) {
      SetConfigurationValue("Account", "UserName", "");
      SetConfigurationValue("Account", "PasswordMD5", "");
    }

    UpdateStatusUI(false, "", 0);
    ShowSuccessNotice(Page, "Account", "Logged out successfully.");

    LoginButton->setEnabled(true);
    LogoutButton->setEnabled(false);
  };

  QObject::connect(LoginButton, &QPushButton::clicked, Page, SendLoginRequest);
  QObject::connect(LogoutButton, &QPushButton::clicked, Page, HandleLogout);

  // Enter 键提交登录
  QObject::connect(LoginPasswordEdit, &QLineEdit::returnPressed, Page,
                   SendLoginRequest);

  // ========== Register Section ==========
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
    Json["Password"] = CalculateSHA256(Password);  // Send SHA-256 hash
    // No UserType field - server will force UserType = 0

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

  // ========== Change Password Section ==========
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
    Json["OldPassword"] = CalculateSHA256(OldPassword);  // Send SHA-256 hash
    Json["NewPassword"] = CalculateSHA256(NewPassword);  // Send SHA-256 hash

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
          if (Username == CurrentUser && RememberMeCheckbox->isChecked()) {
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

  // ========== Change User Type Section ==========
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

  Layout->addLayout(ChangeUserTypeLayout);

  const auto ShowCUTError = [=](const QString &Message) {
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
    Json["AdminPassword"] = CalculateSHA256(AdminPassword);  // Send SHA-256 hash
    Json["TargetUserName"] = TargetUser;
    Json["NewUserType"] = NewUserType;

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

  // ========== 初始化：读取配置并更新状态 ==========
  bool IsLoggedIn =
      ConfigurationValue("Account", "IsLoggedIn", false).toBool();
  QString SavedUsername =
      ConfigurationValue("Account", "UserName", "").toString();
  int SavedUserType = ConfigurationValue("Account", "UserType", 0).toInt();

  if (IsLoggedIn) {
    UpdateStatusUI(true, SavedUsername, SavedUserType);
    LoginButton->setEnabled(false);
    LogoutButton->setEnabled(true);
  }

  // 恢复保存的凭证
  if (ConfigurationValue("Account", "SaveCredentials", false).toBool()) {
    LoginUsernameEdit->setText(SavedUsername);
    QString EncryptedPassword =
        ConfigurationValue("Account", "Password", "").toString();
    if (!EncryptedPassword.isEmpty()) {
      // 不在密码框显示密码，但标记已保存
      LoginPasswordEdit->setPlaceholderText("(Saved)");
    }
  }

  // 自动登录
  if (ConfigurationValue("Account", "AutoLogin", false).toBool() &&
      ConfigurationValue("Account", "SaveCredentials", false).toBool() &&
      !IsLoggedIn) {
    QString SavedPassword = DecryptPassword(
        ConfigurationValue("Account", "Password", "").toString());
    if (!SavedUsername.isEmpty() && !SavedPassword.isEmpty()) {
      QTimer::singleShot(500, [=]() {
        QNetworkRequest Request(QUrl(KServerAddress + "/Login"));
        Request.setHeader(QNetworkRequest::ContentTypeHeader,
                          "application/json");

        QJsonObject Json;
        Json["UserName"] = SavedUsername;
        Json["Password"] = CalculateSHA256(SavedPassword);  // Hash the saved password

        QByteArray Data = QJsonDocument(Json).toJson();

        LoginLoadingRing->setVisible(true);

        QNetworkReply *Reply = NetworkManager->post(Request, Data);

        QObject::connect(Reply, &QNetworkReply::finished, Page, [=]() {
          LoginLoadingRing->setVisible(false);

          if (Reply->error() == QNetworkReply::NoError) {
            QJsonDocument Doc = QJsonDocument::fromJson(Reply->readAll());
            QJsonObject Response = Doc.object();

            if (Response["success"].toBool()) {
              HandleLoginSuccess(Response["data"].toObject());
            }
          }

          Reply->deleteLater();
        });
      });
    }
  }

  // 包装到滚动区域
  auto *Scroll = new ScrollArea;
  Scroll->setWidget(Page);
  Scroll->setWidgetResizable(true);

  return WrapPage(Scroll);
}
