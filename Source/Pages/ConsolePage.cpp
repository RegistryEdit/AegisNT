QWidget *CreateConsolePage() {
  auto *Page = new QWidget;
  auto *Layout = new QVBoxLayout(Page);
  ConfigurePageLayout(Layout, 8);
  auto *Output = new PlainTextEdit;
  InstallFluentScrollBar(Output, Qt::Vertical);
  Output->setReadOnly(true);
  Output->setFont(QFont("Cascadia Mono", 10));
  Output->setPlainText(ConsoleOutputSnapshot());
  ConsoleOutputWidget = Output;
  Layout->addWidget(Output, 1);
  auto *CommandLayout = new QHBoxLayout;
  ConfigureToolbarLayout(CommandLayout);
  auto *Command = new LineEdit;
  Command->setPlaceholderText("Type a command and press Enter");
  auto *Run = MakeButton("Run", true);
  auto *Clear = MakeButton("Clear");
  auto *Copy = MakeButton("Copy");
  auto *Interrupt = MakeButton("Ctrl+C");
  CommandLayout->addWidget(Command, 1);
  CommandLayout->addWidget(Clear);
  CommandLayout->addWidget(Copy);
  CommandLayout->addWidget(Interrupt);
  CommandLayout->addWidget(Run);
  Layout->addLayout(CommandLayout);

  const auto ExecuteCommand = [Page, Command, Run, Interrupt] {
    const QString Text = Command->text().trimmed();
    if (Text.isEmpty() || ActiveConsoleProcess)
      return;
    Command->clear();
    AppendConsoleOutput("console> " + Text + "\n");
    auto *Process = new QProcess(Page);
    ActiveConsoleProcess = Process;
    Process->setProcessChannelMode(QProcess::SeparateChannels);
    Process->setProgram("cmd.exe");
    Process->setArguments(
        {"/d", "/s", "/c", QStringLiteral("chcp 65001>nul & ") + Text});
    Run->setEnabled(false);
    Interrupt->setEnabled(true);
    QObject::connect(
        Process, &QProcess::readyReadStandardOutput, Process, [Process] {
          const QByteArray Bytes = Process->readAllStandardOutput();
          if (!Bytes.isEmpty())
            AppendConsoleOutput(DecodeConsoleProcessOutput(Bytes));
        });
    QObject::connect(Process, &QProcess::readyReadStandardError, Process,
                     [Process] {
                       const QByteArray Bytes = Process->readAllStandardError();
                       if (!Bytes.isEmpty())
                         AppendConsoleOutput(DecodeConsoleProcessOutput(Bytes));
                     });
    QObject::connect(Process, &QProcess::errorOccurred, Process,
                     [Process](QProcess::ProcessError) {
                       AppendConsoleOutput("[!] " + Process->errorString() +
                                           "\n");
                     });
    QObject::connect(
        Process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
        Process,
        [Page, Process, Run, Interrupt](int ExitCode,
                                        QProcess::ExitStatus Status) {
          const QByteArray RemainingStdout = Process->readAllStandardOutput();
          if (!RemainingStdout.isEmpty())
            AppendConsoleOutput(DecodeConsoleProcessOutput(RemainingStdout));
          const QByteArray RemainingStderr = Process->readAllStandardError();
          if (!RemainingStderr.isEmpty())
            AppendConsoleOutput(DecodeConsoleProcessOutput(RemainingStderr));
          if (Status == QProcess::CrashExit) {
            AppendConsoleOutput(
                QString("[!] Command process terminated (exit code %1).\n")
                    .arg(ExitCode));
            ShowErrorNotice(
                Page, "Console",
                QString("Command terminated with exit code %1.").arg(ExitCode));
          } else if (ExitCode == 0)
            ShowSuccessNotice(Page, "Console",
                              "Command completed successfully.");
          else {
            AppendConsoleOutput(
                QString("[!] Command exited with code %1.\n").arg(ExitCode));
            ShowErrorNotice(
                Page, "Console",
                QString("Command completed with exit code %1.").arg(ExitCode));
          }
          ActiveConsoleProcess = nullptr;
          Run->setEnabled(true);
          Interrupt->setEnabled(false);
          Process->deleteLater();
        });
    Process->start();
  };
  QObject::connect(Command, &QLineEdit::returnPressed, Page, ExecuteCommand);
  QObject::connect(Run, &QPushButton::clicked, Page, ExecuteCommand);
  QObject::connect(Clear, &QPushButton::clicked, Page, [Page] {
    ClearConsoleOutput();
    ShowSuccessNotice(Page, "Console", "Console cleared.");
  });
  QObject::connect(Copy, &QPushButton::clicked, Page, [Page] {
    qApp->clipboard()->setText(ConsoleOutputSnapshot());
    AppendConsoleOutput("[*] Copied transcript to clipboard.\n");
    ShowSuccessNotice(Page, "Console", "Transcript copied to the clipboard.");
  });
  QObject::connect(Interrupt, &QPushButton::clicked, Page, [] {
    if (!ActiveConsoleProcess) {
      AppendConsoleOutput("[!] No command is running.\n");
      return;
    }
    AppendConsoleOutput("[*] Ctrl+C requested.\n");
    ShowSuccessNotice(QApplication::activeWindow(), "Console",
                      "Interrupt request sent.");
    ActiveConsoleProcess->terminate();
    QPointer<QProcess> Process = ActiveConsoleProcess;
    QTimer::singleShot(1000, qApp, [Process] {
      if (Process && Process->state() != QProcess::NotRunning)
        Process->kill();
    });
  });
  Interrupt->setEnabled(false);
  return Page;
}
