// 登录对话框:在主窗口创建之前弹出(以及登出后重新弹出)。
// 含 Remember Me / Auto Login,Register 按钮打开注册对话框;
// 登录成功即 accept,调用方据此决定是否创建主窗口。
// 全部控件均为 QFluent;窗口本身应用主题样式表 + 无边框标题栏。

static bool RunLoginDialog(QWidget *Parent, const QString &PresetError) {
  QDialog Dialog(Parent);
  Dialog.setWindowTitle("AegisNT Login");
  Dialog.setModal(true);
  Dialog.setMinimumWidth(380);

  auto *Layout = new QVBoxLayout(&Dialog);
  Layout->setContentsMargins(0, 0, 0, 0);
  Layout->setSpacing(0);
  Layout->addWidget(CreateDialogTitleBar(&Dialog, "AegisNT Login"));

  auto *Content = new QVBoxLayout;
  Content->setContentsMargins(24, 16, 24, 20);
  Content->setSpacing(12);

  Content->addWidget(
      MakeLabel("Sign in to AegisNT", 16, KTextPrimary, QFont::DemiBold));
  Content->addWidget(
      MakeLabel("Sign in is required before the main window opens.", 11,
                KTextMuted));

  auto *UsernameEdit = new LineEdit;
  UsernameEdit->setPlaceholderText("Username");
  UsernameEdit->setText(Account.UserName);
  UsernameEdit->setClearButtonEnabled(true);
  Content->addWidget(UsernameEdit);

  auto *PasswordEdit = new PasswordLineEdit;
  PasswordEdit->setPlaceholderText("Password");
  if (ConfigurationValue("Account", "SaveCredentials", false).toBool() &&
      !ConfigurationValue("Account", "Password", "").toString().isEmpty())
    PasswordEdit->setPlaceholderText("Password (saved)");
  Content->addWidget(PasswordEdit);

  auto *OptionsLayout = new QHBoxLayout;
  auto *RememberMeCheckbox = new CheckBox;
  RememberMeCheckbox->setText("Remember Me");
  RememberMeCheckbox->setChecked(
      ConfigurationValue("Account", "SaveCredentials", false).toBool());
  auto *AutoLoginCheckbox = new CheckBox;
  AutoLoginCheckbox->setText("Auto Login");
  AutoLoginCheckbox->setChecked(
      ConfigurationValue("Account", "AutoLogin", false).toBool());
  OptionsLayout->addWidget(RememberMeCheckbox);
  OptionsLayout->addWidget(AutoLoginCheckbox);
  OptionsLayout->addStretch();
  Content->addLayout(OptionsLayout);

  auto *StatusLayout = new QHBoxLayout;
  auto *LoadingRing = new IndeterminateProgressRing;
  LoadingRing->setFixedSize(24, 24);
  LoadingRing->setVisible(false);
  auto *ErrorLabel = MakeLabel("", 10, KTextMuted);
  ErrorLabel->setVisible(false);
  ErrorLabel->setWordWrap(true);
  StatusLayout->addWidget(LoadingRing);
  StatusLayout->addWidget(ErrorLabel, 1);
  Content->addLayout(StatusLayout);

  auto *ButtonLayout = new QHBoxLayout;
  ButtonLayout->addStretch();
  auto *RegisterButton = MakeButton("Register");
  auto *LoginButton = MakeButton("Login", true);
  ButtonLayout->addWidget(RegisterButton);
  ButtonLayout->addWidget(LoginButton);
  Content->addLayout(ButtonLayout);

  Layout->addLayout(Content);

  const auto SetBusy = [&](bool Busy) {
    UsernameEdit->setEnabled(!Busy);
    PasswordEdit->setEnabled(!Busy);
    RememberMeCheckbox->setEnabled(!Busy);
    AutoLoginCheckbox->setEnabled(!Busy);
    RegisterButton->setEnabled(!Busy);
    LoginButton->setEnabled(!Busy);
    LoadingRing->setVisible(Busy);
  };
  const auto ShowError = [&](const QString &Message) {
    AppendConsoleOutput("[!] Account login: " + Message + "\n");
    ErrorLabel->setText("Error: " + Message);
    const QColor Danger = CurrentThemePalette().Danger;
    ErrorLabel->setTextColor(Danger, Danger);
    ErrorLabel->setVisible(true);
  };

  const auto Submit = [&]() {
    const QString Username = UsernameEdit->text().trimmed();
    const QString Password = PasswordEdit->text();
    if (Username.isEmpty() || Password.isEmpty()) {
      ShowError("Username and password cannot be empty");
      return;
    }

    SetBusy(true);
    ErrorLabel->setVisible(false);

    QJsonObject Body;
    Body["UserName"] = Username;
    Body["Password"] = Sha256Hex(Password);

    // Submit 返回后网络请求才完成；请求凭证必须由回调按值持有。
    // 其余引用属于 RunLoginDialog，连接由 Dialog 的生命周期约束。
    PostJsonRequest("/Login", Body, &Dialog,
                    [&, Username, Password](const QJsonObject &Response, const QString &Error) {
                      SetBusy(false);
                      if (!Error.isEmpty()) {
                        ShowError("Network error: " + Error);
                        return;
                      }
                      if (!Response["success"].toBool()) {
                        ShowError(Response["message"].toString());
                        return;
                      }
                      HandleLoginSuccess(
                          Parent, Response["data"].toObject(), Username,
                          Password, RememberMeCheckbox->isChecked(),
                          AutoLoginCheckbox->isChecked());
                      if (Account.IsLoggedIn)
                        Dialog.accept();
                    });
  };

  QObject::connect(LoginButton, &QPushButton::clicked, &Dialog, Submit);
  QObject::connect(PasswordEdit, &QLineEdit::returnPressed, &Dialog, Submit);
  QObject::connect(AutoLoginCheckbox, &QCheckBox::toggled, &Dialog,
                   [RememberMeCheckbox](bool Checked) {
                     if (Checked)
                       RememberMeCheckbox->setChecked(true);
                   });
  QObject::connect(RegisterButton, &QPushButton::clicked, &Dialog, [&]() {
    RunRegisterDialog(&Dialog, UsernameEdit);
  });

  ApplyDialogTheme(&Dialog);
  return Dialog.exec() == QDialog::Accepted;
}

// 启动/登出后的完整登录流程:
// 1. 勾选了 Auto Login 且保存了凭证时,先静默自动登录(阻塞等待,带超时);
// 2. 失败或未勾选则弹出 Login Dialog(预填用户名,并展示自动登录失败原因)。
// 返回 false 表示用户关闭了登录框,调用方应退出程序。
static bool RunLoginFlow(QWidget *Parent, const QString &PresetError = {}) {
  QString Error = PresetError;
  if (ConfigurationValue("Account", "AutoLogin", false).toBool() &&
      ConfigurationValue("Account", "SaveCredentials", false).toBool()) {
    const QString SavedUsername =
        ConfigurationValue("Account", "UserName", "").toString().trimmed();
    const QString SavedPassword = DecryptPassword(
        ConfigurationValue("Account", "Password", "").toString());
    if (!SavedUsername.isEmpty() && !SavedPassword.isEmpty()) {
      QJsonObject Body;
      Body["UserName"] = SavedUsername;
      Body["Password"] = Sha256Hex(SavedPassword);

      QJsonObject Response;
      QString RequestError;
      if (PostJsonRequestBlocking("/Login", Body, 6000, &Response,
                                  &RequestError)) {
        if (Response["success"].toBool()) {
          HandleLoginSuccess(Parent, Response["data"].toObject(),
                             SavedUsername, SavedPassword, true, true);
          return Account.IsLoggedIn;
        }
        Error = Response["message"].toString();
      } else {
        Error = "Network error: " + RequestError;
      }
      AppendConsoleOutput("[!] Account auto login: " + Error + "\n");
    }
  }
  return RunLoginDialog(Parent, Error);
}
