QWidget *CreateMemoryPage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout);
  auto *Hint =
      MakeLabel("Process ID accepts 0. `0` means kernel mode memory access.",
                11, KTextMuted);
  Hint->setWordWrap(true);
  Layout->addWidget(Hint);
  auto *TargetLayout = new QHBoxLayout;
  ConfigureToolbarLayout(TargetLayout);
  auto *Pid = new LineEdit;
  auto *Address = new LineEdit;
  Pid->setPlaceholderText("Process ID (0 = kernel mode)");
  Address->setPlaceholderText("Address, for example 0x7FF612340000");
  Pid->setMaximumWidth(190);
  TargetLayout->addWidget(Pid);
  TargetLayout->addWidget(Address, 1);
  Layout->addLayout(TargetLayout);
  auto *ReadLayout = new QHBoxLayout;
  ConfigureToolbarLayout(ReadLayout);
  auto *ReadSize = new LineEdit;
  ReadSize->setText("256");
  ReadSize->setPlaceholderText("Read size (1-4096)");
  auto *ReadButton = MakeButton("Read", true);
  ReadLayout->addWidget(ReadSize, 1);
  ReadLayout->addWidget(ReadButton);
  Layout->addLayout(ReadLayout);
  auto *ViewerLayout = new QHBoxLayout;
  ConfigureToolbarLayout(ViewerLayout);
  auto *HexPanel = new QVBoxLayout;
  auto *AsciiPanel = new QVBoxLayout;
  HexPanel->setContentsMargins(0, 0, 0, 0);
  HexPanel->setSpacing(6);
  AsciiPanel->setContentsMargins(0, 0, 0, 0);
  AsciiPanel->setSpacing(6);
  auto *HexLabel = MakeLabel("HEX", 11, KTextMuted);
  auto *AsciiLabel = MakeLabel("ASCII", 11, KTextMuted);
  auto *HexView = new PlainTextEdit;
  auto *AsciiView = new PlainTextEdit;
  HexView->setPlaceholderText(
      "Hex bytes for read/write, for example: 48 8B 05 00 FF");
  AsciiView->setPlaceholderText("ASCII view of the latest read result");
  HexView->setFont(QFont("Cascadia Mono", 10));
  AsciiView->setFont(QFont("Cascadia Mono", 10));
  AsciiView->setReadOnly(true);
  InstallFluentScrollBar(HexView, Qt::Vertical);
  InstallFluentScrollBar(AsciiView, Qt::Vertical);
  HexPanel->addWidget(HexLabel);
  HexPanel->addWidget(HexView, 1);
  AsciiPanel->addWidget(AsciiLabel);
  AsciiPanel->addWidget(AsciiView, 1);
  ViewerLayout->addLayout(HexPanel, 3);
  ViewerLayout->addLayout(AsciiPanel, 2);
  Layout->addLayout(ViewerLayout, 1);
  auto *WriteLayout = new QHBoxLayout;
  ConfigureToolbarLayout(WriteLayout);
  auto *Status = new BodyLabel("Ready");
  auto *WriteButton = MakeButton("Write");
  WriteLayout->addWidget(Status, 1);
  WriteLayout->addWidget(WriteButton);
  Layout->addLayout(WriteLayout);
  const auto ParseTarget = [Page, Pid, Address](ULONG &ProcessId,
                                                ULONG_PTR &TargetAddress) {
    bool PidOk = false, AddressOk = false;
    const qulonglong PidValue = Pid->text().trimmed().toULongLong(&PidOk, 0);
    const qulonglong AddressValue =
        Address->text().trimmed().toULongLong(&AddressOk, 0);
    if (!PidOk || PidValue > std::numeric_limits<ULONG>::max() || !AddressOk ||
        AddressValue == 0) {
      ShowWarningNotice(
          Page, "Memory",
          "Enter a valid PID and address. PID 0 means kernel mode.");
      return false;
    }
    ProcessId = static_cast<ULONG>(PidValue);
    TargetAddress = static_cast<ULONG_PTR>(AddressValue);
    return true;
  };
  QObject::connect(
      ReadButton, &QPushButton::clicked, Page,
      [Page, ReadSize, HexView, AsciiView, Status, ParseTarget] {
        ULONG ProcessId = 0;
        ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress))
          return;
        bool SizeOk = false;
        const uint Size = ReadSize->text().trimmed().toUInt(&SizeOk, 0);
        if (!SizeOk || Size == 0 || Size > 4096) {
          ShowWarningNotice(Page, "Memory",
                            "Read size must be between 1 and 4096.");
          return;
        }
        std::vector<unsigned char> Buffer(Size);
        ULONG BytesRead = 0;
        if (!ReadMemory(ProcessId, TargetAddress, Buffer.data(), Size,
                        &BytesRead)) {
          const QString Message =
              QString("Read failed (error %1)").arg(G_LastMultiDrvError);
          Status->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
          return;
        }
        Buffer.resize(std::min<size_t>(BytesRead, Buffer.size()));
        QString HexOutput;
        QString AsciiOutput;
        for (size_t Offset = 0; Offset < Buffer.size(); Offset += 16) {
          QString HexLine =
              QString("%1  ")
                  .arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16,
                       QLatin1Char('0'))
                  .toUpper();
          QString AsciiLine =
              QString("%1  ")
                  .arg(TargetAddress + Offset, sizeof(ULONG_PTR) * 2, 16,
                       QLatin1Char('0'))
                  .toUpper();
          for (size_t Index = 0; Index < 16; ++Index) {
            if (Offset + Index < Buffer.size()) {
              const unsigned char Value = Buffer[Offset + Index];
              HexLine +=
                  QString("%1 ").arg(Value, 2, 16, QLatin1Char('0')).toUpper();
              AsciiLine += std::isprint(static_cast<int>(Value)) ? QChar(Value)
                                                                 : QChar('.');
            } else {
              HexLine += "   ";
            }
            if (Index == 7)
              HexLine += ' ';
          }
          HexOutput += HexLine.trimmed() + '\n';
          AsciiOutput += AsciiLine + '\n';
        }
        HexView->setPlainText(HexOutput.trimmed());
        AsciiView->setPlainText(AsciiOutput.trimmed());
        const QString Message = QString("Read %1 byte(s).").arg(Buffer.size());
        Status->setText(Message);
        ShowSuccessNotice(Page, "Memory", Message);
      });
  QObject::connect(
      WriteButton, &QPushButton::clicked, Page,
      [Page, HexView, Status, ParseTarget] {
        ULONG ProcessId = 0;
        ULONG_PTR TargetAddress = 0;
        if (!ParseTarget(ProcessId, TargetAddress))
          return;
        QString Text = HexView->toPlainText();
        Text.replace(',', ' ')
            .replace(';', ' ')
            .replace('\n', ' ')
            .replace('\t', ' ')
            .replace('\r', ' ');
        QRegularExpression AddressPrefix("(?i)\\b[0-9a-f]+\\s{2,}");
        Text.replace(AddressPrefix, "");
        const QStringList Tokens = Text.split(' ', Qt::SkipEmptyParts);
        if (Tokens.isEmpty() || Tokens.size() > 4096) {
          ShowWarningNotice(Page, "Memory",
                            "Enter between 1 and 4096 hexadecimal bytes.");
          return;
        }
        std::vector<unsigned char> Bytes;
        Bytes.reserve(Tokens.size());
        for (QString Token : Tokens) {
          if (Token.startsWith("0x", Qt::CaseInsensitive))
            Token.remove(0, 2);
          bool Ok = false;
          const uint Value = Token.toUInt(&Ok, 16);
          if (!Ok || Token.size() > 2 || Value > 0xFF) {
            ShowWarningNotice(Page, "Memory", "Invalid hex byte: " + Token);
            return;
          }
          Bytes.push_back(static_cast<unsigned char>(Value));
        }
        if (!WriteMemory(ProcessId, TargetAddress, Bytes.data(),
                         static_cast<ULONG>(Bytes.size()))) {
          const QString Message =
              QString("Write failed (error %1)").arg(G_LastMultiDrvError);
          Status->setText(Message);
          ShowErrorNotice(Page, "Memory", Message);
        } else {
          const QString Message =
              QString("Wrote %1 byte(s).").arg(Bytes.size());
          Status->setText(Message);
          ShowSuccessNotice(Page, "Memory", Message);
        }
      });
  return Page;
}

#include "Source/Pages/DriverPage.inc"

QWidget *CreateDriverPage() { return new DriverManagerPage; }

#include "Source/Pages/ServicePage.inc"

QWidget *CreateServiceManagerPage() { return new ServiceManagerPage; }
