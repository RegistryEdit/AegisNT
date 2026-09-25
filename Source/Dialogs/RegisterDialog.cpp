// 注册对话框:从 Login Dialog 打开,注册成功后回填用户名。
// 注册请求 POST /Register;服务器强制新账号为普通用户(UserType = 0)。
// 全部控件均为 QFluent;窗口本身应用主题样式表 + 无边框标题栏。

static void RunRegisterDialog(QWidget *Parent, QLineEdit *UsernameBackRef) {
  QDialog Dialog(Parent);
  Dialog.setWindowTitle("Register");
  Dialog.setModal(true);
  Dialog.setMinimumWidth(380);

  auto *Layout = new QVBoxLayout(&Dialog);
  Layout->setContentsMargins(0, 0, 0, 0);
  Layout->setSpacing(0);
  Layout->addWidget(CreateDialogTitleBar(&Dialog, "Register"));

  auto *Content = new QVBoxLayout;
  Content->setContentsMargins(24, 16, 24, 20);
  Content->setSpacing(12);

  Content->addWidget(MakeLabel("Create Account", 16, KTextPrimary,
                               QFont::DemiBold));
  Content->addWidget(MakeLabel(
      "The account will be created as a regular user.", 11, KTextMuted));

  auto *UsernameEdit = new LineEdit;
  UsernameEdit->setPlaceholderText("Username");
  UsernameEdit->setClearButtonEnabled(true);
  if (UsernameBackRef)
    UsernameEdit->setText(UsernameBackRef->text());
  Content->addWidget(UsernameEdit);

  auto *PasswordEdit = new PasswordLineEdit;
  PasswordEdit->setPlaceholderText("Password (at least 6 characters)");
  Content->addWidget(PasswordEdit);

  auto *ConfirmEdit = new PasswordLineEdit;
  ConfirmEdit->setPlaceholderText("Confirm Password");
  Content->addWidget(ConfirmEdit);

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
  auto *SubmitButton = MakeButton("Register", true);
  auto *CancelButton = MakeButton("Cancel");
  ButtonLayout->addWidget(SubmitButton);
  ButtonLayout->addWidget(CancelButton);
  Content->addLayout(ButtonLayout);

  Layout->addLayout(Content);

  const auto SetBusy = [&](bool Busy) {
    UsernameEdit->setEnabled(!Busy);
    PasswordEdit->setEnabled(!Busy);
    ConfirmEdit->setEnabled(!Busy);
    SubmitButton->setEnabled(!Busy);
    LoadingRing->setVisible(Busy);
  };
  const auto ShowError = [&](const QString &Message) {
    AppendConsoleOutput("[!] Account registration: " + Message + "\n");
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
    if (Password.length() < 6) {
      ShowError("Password must be at least 6 characters");
      return;
    }
    if (Password != ConfirmEdit->text()) {
      ShowError("Passwords do not match");
      return;
    }

    SetBusy(true);
    ErrorLabel->setVisible(false);

    QJsonObject Body;
    Body["UserName"] = Username;
    Body["Password"] = Sha256Hex(Password);

    // 请求异步完成时 Submit 的局部 Username 已销毁，回调持有自己的副本。
    PostJsonRequest("/Register", Body, &Dialog,
                    [&, Username](const QJsonObject &Response, const QString &Error) {
                      SetBusy(false);
                      if (!Error.isEmpty()) {
                        ShowError("Network error: " + Error);
                        return;
                      }
                      if (!Response["success"].toBool()) {
                        ShowError(Response["message"].toString());
                        return;
                      }
                      ShowSuccessNotice(
                          Parent, "Account",
                          QString("User '%1' registered successfully!")
                              .arg(Username));
                      if (UsernameBackRef)
                        UsernameBackRef->setText(Username);
                      Dialog.accept();
                    });
  };

  QObject::connect(SubmitButton, &QPushButton::clicked, &Dialog, Submit);
  QObject::connect(PasswordEdit, &QLineEdit::returnPressed, &Dialog, Submit);
  QObject::connect(ConfirmEdit, &QLineEdit::returnPressed, &Dialog, Submit);
  QObject::connect(CancelButton, &QPushButton::clicked, &Dialog,
                   &QDialog::reject);

  ApplyDialogTheme(&Dialog);
  Dialog.exec();
}
