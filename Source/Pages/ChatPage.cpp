#include "../../Server/ChatProtocol.h"

QWidget *CreateChatPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout, 8);

  auto *NoticeCard = new CardWidget;
  auto *NoticeLayout = new QVBoxLayout(NoticeCard);
  NoticeLayout->setContentsMargins(16, 12, 16, 12);
  NoticeLayout->setSpacing(12);
  NoticeLayout->addWidget(MakeGlyph(Fluent::IconType::INFO, 32), 0,
                          Qt::AlignCenter);
  NoticeLayout->addWidget(
      MakeLabel("Login Required", 16, KAccent, QFont::DemiBold), 0,
      Qt::AlignCenter);
  auto *NoticeText = MakeLabel(
      "You must be logged in to use chat. Sign in on the Account page first.",
      12, KTextPrimary);
  NoticeText->setWordWrap(true);
  NoticeLayout->addWidget(NoticeText);
  NoticeLayout->addStretch();
  Layout->addWidget(NoticeCard);

  auto *ChatContent = new QWidget;
  auto *ChatLayout = new QVBoxLayout(ChatContent);
  ChatLayout->setContentsMargins(0, 0, 0, 0);
  ChatLayout->setSpacing(8);
  Layout->addWidget(ChatContent, 1);

  auto *UsersLayout = new QHBoxLayout;
  UsersLayout->setContentsMargins(0, 0, 0, 0);
  UsersLayout->setSpacing(8);
  auto *OnlineLabel =
      MakeLabel("Online Users (0):", 12, KTextPrimary, QFont::DemiBold);
  auto *OnlineList = new QListWidget;
  OnlineList->setMaximumHeight(120);
  InstallFluentScrollBar(OnlineList, Qt::Vertical);
  UsersLayout->addWidget(OnlineLabel, 0, Qt::AlignTop);
  UsersLayout->addWidget(OnlineList, 1);
  ChatLayout->addLayout(UsersLayout);

  auto *ChatOutput = new PlainTextEdit;
  ChatOutput->setReadOnly(true);
  ChatOutput->setFont(QFont("Cascadia Mono", 10));
  InstallFluentScrollBar(ChatOutput, Qt::Vertical);
  ChatLayout->addWidget(ChatOutput, 1);

  auto *ConnectionLayout = new QHBoxLayout;
  ConfigureToolbarLayout(ConnectionLayout);
  auto *ServerInfoLabel = MakeLabel("", 11, KTextPrimary);
  auto *ConnectionLabel = MakeLabel("Disconnected", 11, KTextMuted);
  auto *ConnectButton = MakeButton("Connect", true);
  auto *DisconnectButton = MakeButton("Disconnect");
  DisconnectButton->setEnabled(false);
  ConnectionLayout->addWidget(ServerInfoLabel);
  ConnectionLayout->addWidget(ConnectionLabel);
  ConnectionLayout->addStretch();
  ConnectionLayout->addWidget(ConnectButton);
  ConnectionLayout->addWidget(DisconnectButton);
  ChatLayout->addLayout(ConnectionLayout);

  auto *MessageLayout = new QHBoxLayout;
  ConfigureToolbarLayout(MessageLayout);
  auto *TargetCombo = new ComboBox;
  TargetCombo->addItem("All Users");
  TargetCombo->setMaximumWidth(150);
  auto *MessageEdit = new LineEdit;
  MessageEdit->setPlaceholderText("Type a message");
  auto *SendButton = MakeButton("Send", true);
  MessageLayout->addWidget(MakeLabel("To:", 11, KTextPrimary));
  MessageLayout->addWidget(TargetCombo);
  MessageLayout->addWidget(MessageEdit, 1);
  MessageLayout->addWidget(SendButton);
  ChatLayout->addLayout(MessageLayout);

  auto *Socket = new QTcpSocket(Page);
  auto ClientName = std::make_shared<QString>();
  auto ReceiveBuffer = std::make_shared<QByteArray>();
  auto *OnlineUsersTimer = new QTimer(Page);
  OnlineUsersTimer->setInterval(2000);

  const auto SendFrame = [Socket](ChatPacketType Type, const void *Payload,
                                  qsizetype PayloadSize) {
    const ChatPacketHeader Header{static_cast<std::uint32_t>(Type),
                                  static_cast<std::uint32_t>(PayloadSize)};
    QByteArray Frame;
    Frame.reserve(static_cast<qsizetype>(sizeof(Header)) + PayloadSize);
    Frame.append(reinterpret_cast<const char *>(&Header), sizeof(Header));
    Frame.append(reinterpret_cast<const char *>(Payload), PayloadSize);
    return Socket->write(Frame) == Frame.size();
  };

  const auto UpdateSessionUi = [=]() {
    const bool LoggedIn = Account.IsLoggedIn;
    NoticeCard->setVisible(!LoggedIn);
    ChatContent->setVisible(LoggedIn);

    const QString Host =
        ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
    const QString Port =
        ConfigurationValue("Chat", "ServerPort", "1145").toString();
    ServerInfoLabel->setText(
        QString("Server: %1:%2 | User: %3")
            .arg(Host, Port,
                 Account.UserName.isEmpty() ? "-" : Account.UserName));

    ConnectButton->setEnabled(
        LoggedIn && Socket->state() == QAbstractSocket::UnconnectedState);
    MessageEdit->setEnabled(LoggedIn);
    SendButton->setEnabled(LoggedIn);
    TargetCombo->setEnabled(LoggedIn);
  };

  QObject::connect(ConnectButton, &QPushButton::clicked, Page, [=]() {
    if (!Account.IsLoggedIn || Account.UserName.trimmed().isEmpty()) {
      ChatOutput->appendPlainText("[Error] No logged-in user.");
      return;
    }

    bool PortValid = false;
    quint16 Port = ConfigurationValue("Chat", "ServerPort", "1145")
                       .toString()
                       .toUShort(&PortValid);
    if (!PortValid || Port == 0)
      Port = 1145;

    const QString Host =
        ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
    *ClientName = Account.UserName.trimmed();
    ConnectionLabel->setText("Connecting");
    ConnectButton->setEnabled(false);
    ChatOutput->appendPlainText(
        QString("[System] Connecting to %1:%2 as %3")
            .arg(Host)
            .arg(Port)
            .arg(*ClientName));
    Socket->connectToHost(Host, Port);
  });

  QObject::connect(Socket, &QTcpSocket::connected, Page, [=]() {
    ClientInfo Info{};
    const QByteArray Name = ClientName->toUtf8().left(ChatNameCapacity - 1);
    std::memcpy(Info.ClientName, Name.constData(), Name.size());

    if (!SendFrame(ChatPacketType::ClientInfo, &Info, sizeof(Info))) {
      ChatOutput->appendPlainText("[Error] Failed to send handshake.");
      Socket->abort();
      return;
    }
    Socket->flush();
    ConnectionLabel->setText("Connected");
    ConnectButton->setEnabled(false);
    DisconnectButton->setEnabled(true);
    ChatOutput->appendPlainText(
        QString("[System] Connected as %1").arg(*ClientName));
    OnlineUsersTimer->start();
  });

  QObject::connect(OnlineUsersTimer, &QTimer::timeout, Page, [=]() {
    if (Socket->state() != QAbstractSocket::ConnectedState)
      return;
    const ChatPacketHeader Header{
        static_cast<std::uint32_t>(ChatPacketType::QueryOnlineUsers), 0};
    if (Socket->write(reinterpret_cast<const char *>(&Header), sizeof(Header)) !=
        static_cast<qint64>(sizeof(Header)))
      ChatOutput->appendPlainText("[Error] Failed to query online users.");
  });

  QObject::connect(Socket, &QTcpSocket::readyRead, Page, [=]() {
    *ReceiveBuffer += Socket->readAll();
    while (ReceiveBuffer->size() >=
           static_cast<qsizetype>(sizeof(ChatPacketHeader))) {
      ChatPacketHeader Header{};
      std::memcpy(&Header, ReceiveBuffer->constData(), sizeof(Header));
      if (Header.Size > 1024 * 1024) {
        ChatOutput->appendPlainText("[Error] Invalid packet size.");
        Socket->abort();
        return;
      }

      const qsizetype FrameSize = sizeof(Header) + Header.Size;
      if (ReceiveBuffer->size() < FrameSize)
        return;

      const QByteArray Payload = ReceiveBuffer->mid(sizeof(Header), Header.Size);
      ReceiveBuffer->remove(0, FrameSize);

      if (Header.Type == static_cast<std::uint32_t>(ChatPacketType::Message) &&
          Payload.size() == sizeof(Msg)) {
        Msg Message{};
        std::memcpy(&Message, Payload.constData(), sizeof(Message));
        ChatOutput->appendPlainText(
            QString("[%1]: %2")
                .arg(QString::fromUtf8(Message.From),
                     QString::fromUtf8(Message.Content)));
      } else if (Header.Type ==
                     static_cast<std::uint32_t>(ChatPacketType::OnlineUsers) &&
                 Payload.size() == sizeof(EnumMsg)) {
        EnumMsg Users{};
        std::memcpy(&Users, Payload.constData(), sizeof(Users));
        const int Count = std::clamp(Users.OnlineNumber, 0,
                                     static_cast<int>(ChatMaxOnlineUsers));
        OnlineList->clear();
        TargetCombo->clear();
        TargetCombo->addItem("All Users");
        for (int Index = 0; Index < Count; ++Index) {
          const QString Name = QString::fromUtf8(Users.OnlineUsers[Index]);
          if (Name.isEmpty())
            continue;
          OnlineList->addItem(Name);
          if (Name != *ClientName)
            TargetCombo->addItem(Name);
        }
        TargetCombo->setCurrentIndex(0);
        OnlineLabel->setText(QString("Online Users (%1):").arg(Count));
      } else if (Header.Type ==
                 static_cast<std::uint32_t>(ChatPacketType::Notice)) {
        ChatOutput->appendPlainText(
            QString("[System] %1").arg(QString::fromUtf8(Payload)));
      }
    }
  });

  const auto SendMessage = [=]() {
    ChatOutput->appendPlainText("[Debug] Send invoked");

    const QString Content = MessageEdit->text().trimmed();
    if (Content.isEmpty()) {
      ChatOutput->appendPlainText("[Error] Message is empty.");
      return;
    }
    if (Socket->state() != QAbstractSocket::ConnectedState) {
      ChatOutput->appendPlainText("[Error] Chat is not connected.");
      return;
    }

    Msg Message{};
    const QByteArray From = ClientName->toUtf8().left(ChatNameCapacity - 1);
    const QByteArray Body = Content.toUtf8().left(ChatContentCapacity - 1);
    const QString SelectedTarget = TargetCombo->currentText();
    const QByteArray To =
        (SelectedTarget == "All Users" ? QByteArray("0")
                                       : SelectedTarget.toUtf8())
            .left(ChatNameCapacity - 1);
    std::memcpy(Message.From, From.constData(), From.size());
    std::memcpy(Message.To, To.constData(), To.size());
    std::memcpy(Message.Content, Body.constData(), Body.size());

    if (!SendFrame(ChatPacketType::Message, &Message, sizeof(Message))) {
      ChatOutput->appendPlainText(
          QString("[Error] Send failed: %1").arg(Socket->errorString()));
      return;
    }
    Socket->flush();
    ChatOutput->appendPlainText(
        QString("[You -> %1]: %2").arg(SelectedTarget, Content));
    MessageEdit->clear();
  };

  QObject::connect(SendButton, &QPushButton::clicked, Page, SendMessage);
  QObject::connect(MessageEdit, &QLineEdit::returnPressed, Page, SendMessage);
  QObject::connect(DisconnectButton, &QPushButton::clicked, Page,
                   [=]() { Socket->disconnectFromHost(); });

  QObject::connect(Socket, &QTcpSocket::disconnected, Page, [=]() {
    OnlineUsersTimer->stop();
    ConnectionLabel->setText("Disconnected");
    DisconnectButton->setEnabled(false);
    OnlineList->clear();
    OnlineLabel->setText("Online Users (0):");
    TargetCombo->clear();
    TargetCombo->addItem("All Users");
    TargetCombo->setCurrentIndex(0);
    ReceiveBuffer->clear();
    ClientName->clear();
    ChatOutput->appendPlainText("[System] Disconnected from server.");
    UpdateSessionUi();
  });

  QObject::connect(Socket, &QTcpSocket::errorOccurred, Page,
                   [=](QAbstractSocket::SocketError) {
                     ConnectionLabel->setText("Connection error");
                     ChatOutput->appendPlainText(
                         QString("[Error] %1").arg(Socket->errorString()));
                     UpdateSessionUi();
                   });

  const QPointer<QWidget> PageGuard(Page);
  AegisNT::ApplicationContext().AccountSessionListeners.push_back([=]() {
    if (!PageGuard)
      return false;
    if (!Account.IsLoggedIn &&
        Socket->state() != QAbstractSocket::UnconnectedState)
      Socket->disconnectFromHost();
    UpdateSessionUi();
    return true;
  });

  UpdateSessionUi();
  return Page;
}
