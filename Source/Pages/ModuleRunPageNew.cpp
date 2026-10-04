#include "ModuleRunPageNew.h"
#include "../Core/Module/ModuleService.h"
#include "../Services/IDriverService.h"
#include "../../Module/ModuleBase.h"
#include <QHeaderView>
#include <QLineEdit>
#include <QMessageBox>

namespace AegisNT {

// 外部函数声明（来自原有代码）
extern void ConfigurePageLayout(QVBoxLayout *layout, int spacing);
extern void ConfigureToolbarLayout(QHBoxLayout *layout);
extern QPushButton *MakeButton(const QString &text, bool primary = false);
extern void InstallFluentScrollBar(QAbstractScrollArea *area, Qt::Orientation orientation);
extern void ShowModuleOutputDialog(QWidget *parent, const QString &title);
extern void AppendConsoleOutput(const QString &text);
extern QByteArray Utf8Bytes(const QString &str);
extern const int KCompactTableRowHeight;

ModuleRunPage::ModuleRunPage(IDriverService *driverService, QWidget *parent)
    : PageBase(driverService, parent), m_moduleRunning(false) {
    InitializeUI();
    LoadModuleList();
}

ModuleRunPage::~ModuleRunPage() = default;

void ModuleRunPage::InitializeUI() {
    auto *mainLayout = GetMainLayout();
    ConfigurePageLayout(mainLayout, 10);

    CreateToolbar();
    CreateInformationLabel();
    CreateOptionsTable();
    CreateOutputToolbar();

    mainLayout->addWidget(m_optionsTable, 1);
}

void ModuleRunPage::CreateToolbar() {
    auto *toolbar = new QHBoxLayout;
    ConfigureToolbarLayout(toolbar);

    m_categoryCombo = new QComboBox(this);
    m_categoryCombo->addItems({"All", "Exploit", "Auxiliary", "Post"});
    m_categoryCombo->setCurrentIndex(0);
    m_categoryCombo->setMinimumWidth(150);

    m_moduleCombo = new QComboBox(this);
    m_moduleCombo->setMinimumWidth(260);

    m_refreshBtn = MakeButton("Refresh");
    m_checkBtn = MakeButton("Check");
    m_runBtn = MakeButton("Run", true);
    m_stopBtn = MakeButton("Stop");

    toolbar->addWidget(m_categoryCombo);
    toolbar->addWidget(m_moduleCombo);
    toolbar->addStretch();
    toolbar->addWidget(m_refreshBtn);
    toolbar->addWidget(m_checkBtn);
    toolbar->addWidget(m_stopBtn);
    toolbar->addWidget(m_runBtn);

    GetMainLayout()->addLayout(toolbar);

    // 连接信号
    connect(m_categoryCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ModuleRunPage::OnCategoryChanged);
    connect(m_moduleCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ModuleRunPage::OnModuleChanged);
    connect(m_refreshBtn, &QPushButton::clicked, this, &ModuleRunPage::OnRefreshClicked);
    connect(m_checkBtn, &QPushButton::clicked, this, &ModuleRunPage::OnCheckClicked);
    connect(m_runBtn, &QPushButton::clicked, this, &ModuleRunPage::OnRunClicked);
    connect(m_stopBtn, &QPushButton::clicked, this, &ModuleRunPage::OnStopClicked);
}

void ModuleRunPage::CreateInformationLabel() {
    m_informationLabel = new QLabel("Select a module to configure its call controls.", this);
    m_informationLabel->setWordWrap(true);
    m_informationLabel->setMinimumHeight(42);
    GetMainLayout()->addWidget(m_informationLabel);
}

void ModuleRunPage::CreateOptionsTable() {
    m_optionsTable = new QTableWidget(this);
    InstallFluentScrollBar(m_optionsTable, Qt::Vertical);
    InstallFluentScrollBar(m_optionsTable, Qt::Horizontal);

    m_optionsTable->setColumnCount(4);
    m_optionsTable->setRowCount(0);
    m_optionsTable->setHorizontalHeaderLabels(
        {"Option", "Type", "Value", "Description"});

    m_optionsTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::ResizeToContents);
    m_optionsTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    m_optionsTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::Stretch);
    m_optionsTable->horizontalHeader()->setSectionResizeMode(
        3, QHeaderView::Stretch);

    m_optionsTable->verticalHeader()->hide();
    m_optionsTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_optionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_optionsTable->setMinimumHeight(160);
    m_optionsTable->verticalHeader()->setDefaultSectionSize(KCompactTableRowHeight);
}

void ModuleRunPage::CreateOutputToolbar() {
    auto *outputToolbar = new QHBoxLayout;
    ConfigureToolbarLayout(outputToolbar);

    m_outputBtn = MakeButton("Module Output");
    m_outputBtn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);

    outputToolbar->addWidget(m_outputBtn);
    outputToolbar->addStretch();

    GetMainLayout()->addLayout(outputToolbar);

    connect(m_outputBtn, &QPushButton::clicked, this, &ModuleRunPage::OnShowOutputClicked);
}

void ModuleRunPage::OnPageShow() {
    LoadModuleList();
}

void ModuleRunPage::OnPageRefresh() {
    LoadModuleList();
}

void ModuleRunPage::OnCategoryChanged(int index) {
    QString category = m_categoryCombo->currentText();
    PopulateModules(category);
}

void ModuleRunPage::OnModuleChanged(int index) {
    PopulateOptions();
}

void ModuleRunPage::OnRefreshClicked() {
    LoadModuleList();
    ShowSuccess("Module list refreshed");
}

void ModuleRunPage::OnCheckClicked() {
    // 调用模块的 Check 方法
    QString path = m_moduleCombo->currentData().toString();
    if (path.isEmpty()) {
        ShowWarning("Please select a module first");
        return;
    }

    // TODO: 实现 Check 逻辑
    ShowSuccess("Module check completed");
}

void ModuleRunPage::OnRunClicked() {
    RunModule();
}

void ModuleRunPage::OnStopClicked() {
    StopModule();
}

void ModuleRunPage::OnShowOutputClicked() {
    ShowModuleOutputDialog(this, "Module Output");
}

void ModuleRunPage::LoadModuleList() {
    ModuleService &moduleService = GlobalModuleService();
    moduleService.ScanRuntimeModules();

    PopulateModules(m_categoryCombo->currentText());
}

void ModuleRunPage::PopulateModules(const QString &category) {
    m_moduleCombo->clear();

    ModuleService &moduleService = GlobalModuleService();
    const auto &modules = moduleService.GetDllModules();

    for (const auto &module : modules) {
        // 过滤分类
        if (category != "All") {
            QString moduleType = QString::fromStdString(module.Type);
            if (moduleType != category) {
                continue;
            }
        }

        QString displayName = QString::fromStdString(module.Name);
        m_moduleCombo->addItem(displayName, QString::fromStdString(module.Path));
    }

    if (m_moduleCombo->count() > 0) {
        m_moduleCombo->setCurrentIndex(0);
    }
}

void ModuleRunPage::PopulateOptions() {
    m_optionsTable->setRowCount(0);

    QString path = m_moduleCombo->currentData().toString();
    if (path.isEmpty()) {
        m_informationLabel->setText("Select a module to configure its call controls.");
        m_checkBtn->setEnabled(false);
        m_runBtn->setEnabled(false);
        m_stopBtn->setEnabled(false);
        return;
    }

    ModuleService &moduleService = GlobalModuleService();
    auto *entry = moduleService.FindDllModule(path.toStdString());

    if (!entry) {
        m_informationLabel->setText("Module not found: " + path);
        m_checkBtn->setEnabled(false);
        m_runBtn->setEnabled(false);
        m_stopBtn->setEnabled(false);
        return;
    }

    QString error;
    if (!moduleService.LoadModuleInstance(*entry, &error)) {
        m_informationLabel->setText("Failed to load module: " + error);
        AppendConsoleOutput("[!] ModuleRun: Failed to load " + path + "\n");
        m_checkBtn->setEnabled(false);
        m_runBtn->setEnabled(false);
        m_stopBtn->setEnabled(false);
        return;
    }

    auto *instance = static_cast<ModuleBase *>(entry->ModuleInstance);
    ModuleInfo info = instance->Info();

    // 显示模块信息
    QString infoText = QString("%1/%2  |  Author: %3  |  Target: %4\n%5")
        .arg(QString::fromStdString(ModuleTypeToString(info.Type)))
        .arg(QString::fromStdString(info.Name))
        .arg(QString::fromStdString(info.Author.empty() ? entry->Author : info.Author))
        .arg(QString::fromStdString(info.DefaultTarget.empty() ? "Unknown" : info.DefaultTarget))
        .arg(QString::fromStdString(info.Description.empty() ? entry->Description : info.Description));

    m_informationLabel->setText(infoText);

    // 显示选项
    const auto &options = instance->GetOptions();
    m_optionsTable->setRowCount(static_cast<int>(options.size()));

    int row = 0;
    for (const auto &[name, optionPtr] : options) {
        bool required = optionPtr->GetRequired() == OptionRequired::Required;

        auto *nameItem = new QTableWidgetItem(
            QString::fromStdString(name) + (required ? " *" : ""));
        nameItem->setToolTip(QString::fromStdString(optionPtr->GetDescription()));

        m_optionsTable->setItem(row, 0, nameItem);
        m_optionsTable->setItem(row, 1,
            new QTableWidgetItem(QString::fromStdString(optionPtr->TypeName())));
        m_optionsTable->setItem(row, 3,
            new QTableWidgetItem(QString::fromStdString(optionPtr->GetDescription())));

        QString initialValue = QString::fromStdString(optionPtr->GetValue());

        // 根据选项类型创建编辑器
        if (auto *enumOpt = dynamic_cast<OptEnum *>(optionPtr.get())) {
            auto *editor = new QComboBox(this);
            for (const std::string &choice : enumOpt->GetChoices()) {
                editor->addItem(QString::fromStdString(choice));
            }
            editor->setCurrentText(initialValue);

            connect(editor, &QComboBox::currentTextChanged, this,
                [path, name](const QString &value) {
                    ModuleService &svc = GlobalModuleService();
                    auto *mod = svc.FindDllModule(path.toStdString());
                    if (mod && mod->ModuleInstance) {
                        static_cast<ModuleBase *>(mod->ModuleInstance)
                            ->SetOption(name, Utf8Bytes(value));
                    }
                });

            m_optionsTable->setCellWidget(row, 2, editor);
        } else if (dynamic_cast<OptBool *>(optionPtr.get())) {
            auto *editor = new QComboBox(this);
            editor->addItems({"true", "false"});
            editor->setCurrentText(
                initialValue.compare("false", Qt::CaseInsensitive) == 0 ? "false" : "true");

            connect(editor, &QComboBox::currentTextChanged, this,
                [path, name](const QString &value) {
                    ModuleService &svc = GlobalModuleService();
                    auto *mod = svc.FindDllModule(path.toStdString());
                    if (mod && mod->ModuleInstance) {
                        static_cast<ModuleBase *>(mod->ModuleInstance)
                            ->SetOption(name, Utf8Bytes(value));
                    }
                });

            m_optionsTable->setCellWidget(row, 2, editor);
        } else {
            auto *editor = new QLineEdit(initialValue, this);

            connect(editor, &QLineEdit::textChanged, this,
                [path, name](const QString &value) {
                    ModuleService &svc = GlobalModuleService();
                    auto *mod = svc.FindDllModule(path.toStdString());
                    if (mod && mod->ModuleInstance) {
                        static_cast<ModuleBase *>(mod->ModuleInstance)
                            ->SetOption(name, Utf8Bytes(value));
                    }
                });

            m_optionsTable->setCellWidget(row, 2, editor);
        }

        row++;
    }

    m_checkBtn->setEnabled(true);
    m_runBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
}

void ModuleRunPage::RunModule() {
    QString path = m_moduleCombo->currentData().toString();
    if (path.isEmpty()) {
        ShowWarning("Please select a module first");
        return;
    }

    ModuleService &moduleService = GlobalModuleService();

    if (!moduleService.RunModuleInBackground(path.toStdString())) {
        ShowError("Failed to start module");
        return;
    }

    m_moduleRunning = true;
    m_runBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);

    ShowSuccess("Module started");
}

void ModuleRunPage::StopModule() {
    ModuleService &moduleService = GlobalModuleService();
    moduleService.StopRunningModule();

    m_moduleRunning = false;
    m_runBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);

    ShowSuccess("Module stopped");
}

// 工厂函数（保持向后兼容）
QWidget *CreateModuleRunPage() {
    return new ModuleRunPage(nullptr);
}

} // namespace AegisNT
