#pragma once

#include <QApplication>
#include <QDialog>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QKeySequenceEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QTreeView>
#include <QTreeWidget>
#include <QVBoxLayout>
#pragma push_macro("DELETE")
#pragma push_macro("ERROR")
#pragma push_macro("TRANSPARENT")
#undef DELETE
#undef ERROR
#undef TRANSPARENT
#include <QFluent/Label.h>
#include <QFluent/LineEdit.h>
#include <QFluent/PushButton.h>
#include <QFluent/ScrollBar.h>
#include <QFluent/StyleSheet.h>
#include <QFluent/TextEdit.h>
#include <QFluent/Theme.h>
#pragma pop_macro("DELETE")
#pragma pop_macro("ERROR")
#pragma pop_macro("TRANSPARENT")

namespace AegisNT {

inline QString FluentSurfaceStyle(bool Dark) {
  return QStringLiteral(
      "QDialog[FluentSurface=\"true\"] { background: %1; color: %2; }"
      "QFileDialog QLabel { color: %2; }"
      "QFileDialog QListView { background: %3; color: %2; border: 1px solid %4;"
      " border-radius: 4px; selection-background-color: %6; }"
      "QFileDialog QHeaderView::section { background: %1; color: %2;"
      " border: none; border-bottom: 1px solid %4; padding: 6px; }"
      "QHeaderView[FluentHeader=\"true\"]::section { background: %1; color: %2;"
      " border: none; border-bottom: 1px solid %4; padding: 6px; }"
      "QKeySequenceEdit { background: %3; color: %2; border: 1px solid %4;"
      " border-bottom: 2px solid %4; border-radius: 4px; padding: 4px; }"
      "QKeySequenceEdit:focus { border-bottom-color: %5; }"
      "QKeySequenceEdit QLineEdit { background: transparent; border: none; }"
      "QTreeView[FluentTree=\"true\"] { background: %3; color: %2;"
      " border: 1px solid %4; border-radius: 4px; outline: 0;"
      " selection-background-color: %6; selection-color: %2; }"
      "QTreeView[FluentTree=\"true\"]::item { padding: 5px 4px;"
      " border: none; border-radius: 4px; }"
      "QTreeView[FluentTree=\"true\"]::item:hover { background: %7; }"
      "QTreeView[FluentTree=\"true\"]::item:selected { background: %6; }"
      "QTreeView[FluentTree=\"true\"] QHeaderView::section { background: %1;"
      " color: %2; border: none; border-bottom: 1px solid %4; padding: 6px; }")
      .arg(Dark ? "#202020" : "#f9f9f9", Dark ? "#ffffff" : "#1a1a1a",
           Dark ? "#2b2b2b" : "#ffffff", Dark ? "#454545" : "#d6d6d6",
           Theme::themeColor().name(), Dark ? "#3a3a3a" : "#e9e9e9",
           Dark ? "#333333" : "#f3f3f3");
}

inline void ApplyCustomFluentStyle(QWidget *Widget, const QString &Light,
                                  const QString &Dark) {
  auto Source = std::make_shared<CustomStyleSheet>(Widget);
  Source->setCustomStyleSheet(Light, Dark);
  StyleSheet::setStyleSheet(Widget, Source);
}

inline void RegisterFluentSurface(QWidget *Widget) {
  ApplyCustomFluentStyle(Widget, FluentSurfaceStyle(false),
                         FluentSurfaceStyle(true));
}

inline void InstallCompatibilityScrollBars(QAbstractScrollArea *Area) {
  if (Area->property("FluentCompatibilityScrollBars").toBool())
    return;
  Area->setProperty("FluentCompatibilityScrollBars", true);
  for (const Qt::Orientation Orientation : {Qt::Vertical, Qt::Horizontal}) {
    const char *Key = Orientation == Qt::Vertical ? "FluentScrollBarVertical"
                                                 : "FluentScrollBarHorizontal";
    if (Area->property(Key).toBool())
      continue;
    Area->setProperty(Key, true);
    QScrollBar *Original = Orientation == Qt::Vertical
                              ? Area->verticalScrollBar()
                              : Area->horizontalScrollBar();
    auto *Overlay = new ScrollBar(Original, Area);
    Overlay->setAnimationEnabled(true);
  }
}

template <class Base>
class FluentTreeBase : public Base {
public:
  explicit FluentTreeBase(QWidget *Parent = nullptr) : Base(Parent) {
    this->setProperty("FluentTree", true);
    this->setProperty("FluentCompatibilityStyled", true);
    this->setMouseTracking(true);
    RegisterFluentSurface(this);
    InstallCompatibilityScrollBars(this);
    Theme::onThemeColorChanged(this, [this](const QColor &) {
      RegisterFluentSurface(this);
    });
  }
};

using FluentTreeView = FluentTreeBase<QTreeView>;
using FluentTreeWidget = FluentTreeBase<QTreeWidget>;

class FluentKeySequenceEdit : public QKeySequenceEdit {
public:
  explicit FluentKeySequenceEdit(QWidget *Parent = nullptr)
      : QKeySequenceEdit(Parent) {
    setProperty("FluentCompatibilityStyled", true);
    RegisterFluentSurface(this);
    Theme::onThemeColorChanged(this, [this](const QColor &) {
      RegisterFluentSurface(this);
    });
  }
};

// Qt-owned file-dialog controls and delegates cannot be replaced without losing
// their models. Register only native classes, leaving QFluent subclasses alone.
class FluentCompatibilityFilter final : public QObject {
public:
  using QObject::QObject;

  static void Apply(QWidget *Widget) {
    if (!Widget || Widget->property("FluentCompatibilityStyled").toBool() ||
        StyleSheet::isRegistered(Widget))
      return;
    const QByteArray Class = Widget->metaObject()->className();
    Fluent::ThemeStyle Type;
    if (Class == "QPushButton" || Class == "QToolButton")
      Type = Fluent::ThemeStyle::BUTTON;
    else if (Class == "QLineEdit" || Class == "QTextEdit" ||
             Class == "QPlainTextEdit")
      Type = Fluent::ThemeStyle::LINE_EDIT;
    else if (Class == "QCheckBox" || Class == "QRadioButton")
      Type = Fluent::ThemeStyle::CHECK_BOX;
    else if (Class == "QComboBox")
      Type = Fluent::ThemeStyle::COMBO_BOX;
    else if (Class == "QSpinBox" || Class == "QDoubleSpinBox")
      Type = Fluent::ThemeStyle::SPIN_BOX;
    else if (Class == "QListView" || Class == "QListWidget")
      Type = Fluent::ThemeStyle::LIST_VIEW;
    else if (Class == "QTableView" || Class == "QTableWidget")
      Type = Fluent::ThemeStyle::TABLE_VIEW;
    else if (Class == "QMenu")
      Type = Fluent::ThemeStyle::MENU;
    else if (Class == "QDialog" || Class == "QFileDialog" ||
             Class == "QTreeView" || Class == "QTreeWidget" ||
             Class == "QKeySequenceEdit" || Class == "QHeaderView") {
      Widget->setProperty("FluentCompatibilityStyled", true);
      if (qobject_cast<QDialog *>(Widget))
        Widget->setProperty("FluentSurface", true);
      if (qobject_cast<QTreeView *>(Widget))
        Widget->setProperty("FluentTree", true);
      if (Class == "QHeaderView")
        Widget->setProperty("FluentHeader", true);
      RegisterFluentSurface(Widget);
      Theme::onThemeColorChanged(Widget, [Widget](const QColor &) {
        RegisterFluentSurface(Widget);
      });
      if (auto *Area = qobject_cast<QAbstractScrollArea *>(Widget))
        InstallCompatibilityScrollBars(Area);
      return;
    } else {
      return;
    }
    Widget->setProperty("FluentCompatibilityStyled", true);
    // Native controls need the same selectors as their QFluent counterparts.
    const auto Adapt = [Type](Fluent::ThemeMode Mode) {
      QString Qss = FluentStyleSheet(Type).content(Mode);
      for (const QString &Name : {QStringLiteral("PushButton"),
                                 QStringLiteral("ToolButton"),
                                 QStringLiteral("LineEdit"),
                                 QStringLiteral("CheckBox"),
                                 QStringLiteral("ComboBox"),
                                 QStringLiteral("SpinBox"),
                                 QStringLiteral("ListView"),
                                 QStringLiteral("ListWidget"),
                                 QStringLiteral("TableView"),
                                 QStringLiteral("TableWidget")}) {
        // Word boundaries avoid rewriting selectors already prefixed with Q.
        Qss.replace(QRegularExpression("\\b" + Name + "\\b"), "Q" + Name);
      }
      return Qss;
    };
    ApplyCustomFluentStyle(Widget, Adapt(Fluent::ThemeMode::LIGHT),
                           Adapt(Fluent::ThemeMode::DARK));
    if (auto *Area = qobject_cast<QAbstractScrollArea *>(Widget))
      InstallCompatibilityScrollBars(Area);
  }

protected:
  bool eventFilter(QObject *Watched, QEvent *Event) override {
    if (Event->type() == QEvent::Polish || Event->type() == QEvent::Show)
      Apply(qobject_cast<QWidget *>(Watched));
    return QObject::eventFilter(Watched, Event);
  }
};

inline void InstallFluentCompatibility(QApplication &Application) {
  Application.installEventFilter(new FluentCompatibilityFilter(&Application));
}

class FluentInputDialog {
public:
  static QString getText(QWidget *Parent, const QString &Title,
                         const QString &Label,
                         QLineEdit::EchoMode Echo = QLineEdit::Normal,
                         const QString &Text = {}, bool *Ok = nullptr,
                         Qt::WindowFlags Flags = {},
                         Qt::InputMethodHints Hints = Qt::ImhNone) {
    return Run(Parent, Title, Label, Text, Ok, Flags, Hints, false, Echo);
  }

  static QString getMultiLineText(QWidget *Parent, const QString &Title,
                                  const QString &Label, const QString &Text = {},
                                  bool *Ok = nullptr, Qt::WindowFlags Flags = {},
                                  Qt::InputMethodHints Hints = Qt::ImhNone) {
    return Run(Parent, Title, Label, Text, Ok, Flags, Hints, true,
               QLineEdit::Normal);
  }

private:
  static QString Run(QWidget *Parent, const QString &Title, const QString &Label,
                     const QString &Text, bool *Ok, Qt::WindowFlags Flags,
                     Qt::InputMethodHints Hints, bool MultiLine,
                     QLineEdit::EchoMode Echo) {
    if (Ok)
      *Ok = false;
    QDialog Dialog(Parent, Flags);
    Dialog.setProperty("FluentSurface", true);
    RegisterFluentSurface(&Dialog);
    Dialog.setWindowTitle(Title);
    Dialog.setMinimumWidth(420);
    auto *Layout = new QVBoxLayout(&Dialog);
    Layout->setContentsMargins(24, 20, 24, 20);
    Layout->setSpacing(12);
    Layout->addWidget(new SubtitleLabel(Title, &Dialog));
    auto *Prompt = new BodyLabel(Label, &Dialog);
    Prompt->setWordWrap(true);
    Layout->addWidget(Prompt);
    auto *Single = MultiLine ? nullptr : new LineEdit(&Dialog);
    auto *Multi = MultiLine ? new PlainTextEdit(&Dialog) : nullptr;
    if (Single) {
      Single->setEchoMode(Echo);
      Single->setText(Text);
      Single->setInputMethodHints(Hints);
      Single->selectAll();
      Layout->addWidget(Single);
      Single->setFocus();
      QObject::connect(Single, &QLineEdit::returnPressed, &Dialog, &QDialog::accept);
    } else {
      Multi->setPlainText(Text);
      Multi->setInputMethodHints(Hints);
      Multi->setMinimumHeight(180);
      Layout->addWidget(Multi);
      Multi->setFocus();
    }
    auto *Buttons = new QHBoxLayout;
    Buttons->addStretch();
    auto *Cancel = new PushButton(QApplication::translate("QDialogButtonBox", "Cancel"), &Dialog);
    auto *Accept = new PrimaryPushButton(QApplication::translate("QDialogButtonBox", "OK"), &Dialog);
    Accept->setDefault(true);
    Buttons->addWidget(Cancel);
    Buttons->addWidget(Accept);
    Layout->addLayout(Buttons);
    QObject::connect(Cancel, &QPushButton::clicked, &Dialog, &QDialog::reject);
    QObject::connect(Accept, &QPushButton::clicked, &Dialog, &QDialog::accept);
    const bool Accepted = Dialog.exec() == QDialog::Accepted;
    if (Ok)
      *Ok = Accepted;
    return Accepted ? (Single ? Single->text() : Multi->toPlainText()) : QString();
  }
};

class FluentFileDialog : public QFileDialog {
public:
  explicit FluentFileDialog(QWidget *Parent = nullptr, const QString &Caption = {},
                             const QString &Directory = {}, const QString &Filter = {})
      : QFileDialog(Parent, Caption, Directory, Filter) {
    setOption(QFileDialog::DontUseNativeDialog);
    setProperty("FluentSurface", true);
    RegisterFluentSurface(this);
    resize(800, 520);
  }

  static QString getOpenFileName(QWidget *Parent = nullptr, const QString &Caption = {},
                                const QString &Directory = {}, const QString &Filter = {},
                                QString *SelectedFilter = nullptr, Options OptionsValue = {}) {
    return Choose(Parent, Caption, Directory, Filter, SelectedFilter,
                  OptionsValue, ExistingFile, AcceptOpen);
  }
  static QString getSaveFileName(QWidget *Parent = nullptr, const QString &Caption = {},
                                const QString &Directory = {}, const QString &Filter = {},
                                QString *SelectedFilter = nullptr, Options OptionsValue = {}) {
    return Choose(Parent, Caption, Directory, Filter, SelectedFilter,
                  OptionsValue, AnyFile, AcceptSave);
  }
  static QString getExistingDirectory(QWidget *Parent = nullptr, const QString &Caption = {},
                                     const QString &DirectoryValue = {},
                                     Options OptionsValue = ShowDirsOnly) {
    return Choose(Parent, Caption, DirectoryValue, {}, nullptr, OptionsValue,
                  Directory, AcceptOpen);
  }

private:
  static QString Choose(QWidget *Parent, const QString &Caption,
                        const QString &DirectoryValue, const QString &Filter,
                        QString *SelectedFilter, Options OptionsValue,
                        FileMode Mode, AcceptMode Accept) {
    FluentFileDialog Dialog(Parent, Caption, DirectoryValue, Filter);
    Dialog.setOptions(OptionsValue | DontUseNativeDialog);
    Dialog.setFileMode(Mode);
    Dialog.setAcceptMode(Accept);
    if (SelectedFilter && !SelectedFilter->isEmpty())
      Dialog.selectNameFilter(*SelectedFilter);
    if (Dialog.exec() != QDialog::Accepted || Dialog.selectedFiles().isEmpty())
      return {};
    if (SelectedFilter)
      *SelectedFilter = Dialog.selectedNameFilter();
    return Dialog.selectedFiles().constFirst();
  }
};

inline void ShowFluentMessage(QWidget *Parent, const QString &Title,
                              const QString &Content) {
  QDialog Dialog(Parent);
  Dialog.setProperty("FluentSurface", true);
  RegisterFluentSurface(&Dialog);
  Dialog.setWindowTitle(Title);
  Dialog.setMinimumWidth(380);
  auto *Layout = new QVBoxLayout(&Dialog);
  Layout->setContentsMargins(24, 20, 24, 20);
  Layout->setSpacing(16);
  Layout->addWidget(new SubtitleLabel(Title, &Dialog));
  auto *Message = new BodyLabel(Content, &Dialog);
  Message->setWordWrap(true);
  Message->setTextInteractionFlags(Qt::TextSelectableByMouse);
  Layout->addWidget(Message);
  auto *Close = new PrimaryPushButton(QApplication::translate("QDialogButtonBox", "OK"), &Dialog);
  Close->setDefault(true);
  Layout->addWidget(Close, 0, Qt::AlignRight);
  QObject::connect(Close, &QPushButton::clicked, &Dialog, &QDialog::accept);
  Dialog.exec();
}

} // namespace AegisNT
