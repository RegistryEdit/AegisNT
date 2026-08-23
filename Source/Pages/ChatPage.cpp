#include "../../Server/ChatProtocol.h"

QWidget *CreateChatPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout, 8);

  // 检查登录状态
  bool IsLoggedIn = ConfigurationValue("Account", "IsLoggedIn", false).toBool();
  QString LoggedInUser = ConfigurationValue("Account", "UserName", "").toString();

  // 如果未登录，显示提示
  if (!IsLoggedIn) {
    auto *NoticeCard = new CardWidget;
    auto *NoticeLayout = new QVBoxLayout(NoticeCard);
    NoticeLayout->setContentsMargins(16, 12, 16, 12);
    NoticeLayout->setSpacing(12);
    
    auto *NoticeIcon = MakeGlyph(Fluent::IconType::INFO, 32);
    auto *NoticeTitle = MakeLabel("Login Required", 16, KAccent, QFont::DemiBold);
    auto *NoticeText = MakeLabel("You must be logged in to use the chat feature. Please go to the Account page to login.", 12, KTextPrimary);
    NoticeText->setWordWrap(true);
    
    NoticeLayout->addWidget(NoticeIcon, 0, Qt::AlignCenter);
    NoticeLayout->addWidget(NoticeTitle, 0, Qt::AlignCenter);
    NoticeLayout->addWidget(NoticeText);
    NoticeLayout->addStretch();
    
    Layout->addWidget(NoticeCard);
    Layout->addStretch();
    
    return WrapPage(Page);
  }

  // 在线用户列表
  auto *TopLayout = new QHBoxLayout;
  TopLayout->setContentsMargins(0, 0, 0, 0);
  TopLayout->setSpacing(8);
  
  auto *OnlineLabel = MakeLabel("Online Users:", 12, KTextPrimary, QFont::DemiBold);
  auto *OnlineList = new QListWidget;
  OnlineList->setMaximumHeight(120);
  InstallFluentScrollBar(OnlineList, Qt::Vertical);
  
  TopLayout->addWidget(OnlineLabel, 0, Qt::AlignTop);
  TopLayout->addWidget(OnlineList, 1);
  Layout->addLayout(TopLayout);

  // 聊天消息显示区域
  auto *ChatOutput = new PlainTextEdit;
  InstallFluentScrollBar(ChatOutput, Qt::Vertical); 
  ChatOutput->setReadOnly(true);
  ChatOutput->setFont(QFont("Cascadia Mono", 10));
  Layout->addWidget(ChatOutput, 1);

  // 连接控制区域
  auto *ConnectLayout = new QHBoxLayout;
  ConfigureToolbarLayout(ConnectLayout);
  
  // 使用登录的用户名
  QString ServerIP = ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
  QString ServerPort = ConfigurationValue("Chat", "ServerPort", "1145").toString();
  
  auto *ServerInfoLabel = MakeLabel(
    QString("Server: %1:%2 | Logged in as: %3").arg(ServerIP, ServerPort, LoggedInUser),
    11, KTextPrimary);
  
  auto *ConnectBtn = MakeButton("Connect", true);
  auto *DisconnectBtn = MakeButton("Disconnect");
  DisconnectBtn->setEnabled(false);
  
  ConnectLayout->addWidget(ServerInfoLabel);
  ConnectLayout->addStretch();
  ConnectLayout->addWidget(ConnectBtn);
  ConnectLayout->addWidget(DisconnectBtn);
  
  Layout->addLayout(ConnectLayout);

  // 消息发送区域
  auto *MessageLayout = new QHBoxLayout;
  ConfigureToolbarLayout(MessageLayout);
  
  auto *TargetCombo = new ComboBox;
  TargetCombo->addItem("All Users");
  TargetCombo->setMaximumWidth(150);
  TargetCombo->setEnabled(false);
  
  auto *MessageEdit = new LineEdit;
  MessageEdit->setPlaceholderText("Type a message and press Enter or click Send");
  MessageEdit->setEnabled(false);
  
  auto *SendBtn = MakeButton("Send", true);
  SendBtn->setEnabled(false);
  
  MessageLayout->addWidget(MakeLabel("To:", 11, KTextPrimary));
  MessageLayout->addWidget(TargetCombo);
  MessageLayout->addWidget(MessageEdit, 1);
  MessageLayout->addWidget(SendBtn);
  
  Layout->addLayout(MessageLayout);

  // Socket 连接管理
  QTcpSocket *ClientSocket = new QTcpSocket(Page);
  QString ClientName;
  
  // 连接按钮处理
  QObject::connect(ConnectBtn, &QPushButton::clicked, Page, [=]() mutable {
    // 从配置文件读取服务器信息和登录用户名
    QString Server = ConfigurationValue("Chat", "ServerIP", "127.0.0.1").toString();
    QString PortStr = ConfigurationValue("Chat", "ServerPort", "1145").toString();
    QString Name = ConfigurationValue("Account", "UserName", "").toString();
    
    if (Name.isEmpty()) {
      ChatOutput->appendPlainText("[System] Error: Not logged in. Please login first.");
      return;
    }
    
    bool Ok = false;
    quint16 Port = PortStr.toUShort(&Ok);
    if (!Ok || Port == 0)
      Port = 1145;
    
    ClientName = Name;
    ChatOutput->appendPlainText(QString("[System] Connecting to %1:%2 as %3...")
                                .arg(Server).arg(Port).arg(ClientName));
    ClientSocket->connectToHost(Server, Port);
  });
  
  // 连接成功处理
  QObject::connect(ClientSocket, &QTcpSocket::connected, Page, [=]() mutable {
    ChatOutput->appendPlainText("[System] Connected to server!");
    
    // 发送客户端信息
    ClientInfo Info;
    Info.Type = 0;
    std::string NameStd = ClientName.toStdString();
    if (NameStd.length() >= sizeof(Info.ClientName))
      NameStd.resize(sizeof(Info.ClientName) - 1);
    std::strncpy(Info.ClientName, NameStd.c_str(), sizeof(Info.ClientName) - 1);
    Info.ClientName[sizeof(Info.ClientName) - 1] = '\0';
    
    ClientSocket->write(reinterpret_cast<const char*>(&Info), sizeof(Info));
    ClientSocket->flush();
    
    ConnectBtn->setEnabled(false);
    DisconnectBtn->setEnabled(true);
    MessageEdit->setEnabled(true);
    SendBtn->setEnabled(true);
    TargetCombo->setEnabled(true);
  });
  
  // 接收数据处理
  QObject::connect(ClientSocket, &QTcpSocket::readyRead, Page, [=]() mutable {
    while (ClientSocket->bytesAvailable() > 0) {
      // 尝试读取 Msg 结构
      if (ClientSocket->bytesAvailable() >= static_cast<qint64>(sizeof(Msg))) {
        Msg RecvMsg;
        qint64 BytesRead = ClientSocket->read(reinterpret_cast<char*>(&RecvMsg), sizeof(RecvMsg));
        
        if (BytesRead == sizeof(RecvMsg)) {
          QString From = QString::fromStdString(RecvMsg.From);
          QString Content = QString::fromStdString(RecvMsg.Content);
          ChatOutput->appendPlainText(QString("[%1]: %2").arg(From, Content));
          continue;
        }
      }
      
      // 尝试读取 EnumMsg 结构
      if (ClientSocket->bytesAvailable() >= static_cast<qint64>(sizeof(EnumMsg))) {
        EnumMsg RecvEnum;
        qint64 BytesRead = ClientSocket->read(reinterpret_cast<char*>(&RecvEnum), sizeof(RecvEnum));
        
        if (BytesRead == sizeof(RecvEnum)) {
          OnlineList->clear();
          TargetCombo->clear();
          TargetCombo->addItem("All Users");
          
          const int UserCount = std::clamp(
              RecvEnum.OnlineNumber, 0,
              static_cast<int>(ChatMaxOnlineUsers));
          for (int UserIndex = 0; UserIndex < UserCount; ++UserIndex) {
            QString UserName =
                QString::fromUtf8(RecvEnum.OnlineUsers[UserIndex]);
            OnlineList->addItem(UserName);
            if (UserName != ClientName) {
              TargetCombo->addItem(UserName);
            }
          }
          
          ChatOutput->appendPlainText(QString("[System] %1 user(s) online")
                                      .arg(RecvEnum.OnlineNumber));
          continue;
        }
      }
      
      // 读取普通字符串消息
      QByteArray Data = ClientSocket->readAll();
      if (!Data.isEmpty()) {
        QString Text = QString::fromUtf8(Data);
        ChatOutput->appendPlainText(QString("[System] %1").arg(Text));
      }
    }
  });
  
  // 断开连接处理
  QObject::connect(ClientSocket, &QTcpSocket::disconnected, Page, [=]() mutable {
    ChatOutput->appendPlainText("[System] Disconnected from server");
    ConnectBtn->setEnabled(true);
    DisconnectBtn->setEnabled(false);
    MessageEdit->setEnabled(false);
    SendBtn->setEnabled(false);
    TargetCombo->setEnabled(false);
    OnlineList->clear();
  });
  
  // 错误处理
  QObject::connect(ClientSocket, &QTcpSocket::errorOccurred, Page, 
                   [=](QAbstractSocket::SocketError Error) {
    Q_UNUSED(Error);
    QString ErrorMsg = ClientSocket->errorString();
    ChatOutput->appendPlainText(QString("[Error] %1").arg(ErrorMsg));
    ShowErrorNotice(Page, "Connection Error", ErrorMsg);
  });
  
  // 断开连接按钮处理
  QObject::connect(DisconnectBtn, &QPushButton::clicked, Page, [=]() {
    if (ClientSocket->state() == QAbstractSocket::ConnectedState) {
      ClientSocket->disconnectFromHost();
    }
  });
  
  // 发送消息函数
    const auto SendMessage = [=]() mutable {
  const auto SendMessage = [=]() mutable {
    if (ClientSocket->state() != QAbstractSocket::ConnectedState) {
      ShowErrorNotice(Page, "Error", "Not connected to server");
      return;
    }
    
    QString Content = MessageEdit->text().trimmed();
    if (Content.isEmpty())
      return;
    
    Msg SendMsg;
    SendMsg.FromType = 0;
    
    std::string FromStd = ClientName.toStdString();
    std::string ContentStd = Content.toStdString();
    
    if (FromStd.length() >= sizeof(SendMsg.From))
      FromStd.resize(sizeof(SendMsg.From) - 1);
    if (ContentStd.length() >= sizeof(SendMsg.Content))
      ContentStd.resize(sizeof(SendMsg.Content) - 1);
    
    std::strncpy(SendMsg.From, FromStd.c_str(), sizeof(SendMsg.From) - 1);
    SendMsg.From[sizeof(SendMsg.From) - 1] = '\0';
    
    std::strncpy(SendMsg.Content, ContentStd.c_str(), sizeof(SendMsg.Content) - 1);
    SendMsg.Content[sizeof(SendMsg.Content) - 1] = '\0';
    
    // 设置接收者
    QString Target = TargetCombo->currentText();
    if (Target == "All Users") {
      std::strcpy(SendMsg.To, "0");
    } else {
      std::string ToStd = Target.toStdString();
      if (ToStd.length() >= sizeof(SendMsg.To))
        ToStd.resize(sizeof(SendMsg.To) - 1);
      std::strncpy(SendMsg.To, ToStd.c_str(), sizeof(SendMsg.To) - 1);
      SendMsg.To[sizeof(SendMsg.To) - 1] = '\0';
    }
    
    ClientSocket->write(reinterpret_cast<const char*>(&SendMsg), sizeof(SendMsg));
    ClientSocket->flush();
    
    ChatOutput->appendPlainText(QString("[You -> %1]: %2").arg(Target, Content));
    MessageEdit->clear();
  };
  
  // 发送按钮
  };
  QObject::connect(SendBtn, &QPushButton::clicked, Page, SendMessage);
  
  // 回车发送
  QObject::connect(MessageEdit, &QLineEdit::returnPressed, Page, SendMessage);
  
  return Page;
}
