#pragma once

#include <QFluent/ToolButton.h>
#include <QFluent/Theme.h>
#include <QPainter>
#include <QStyle>

class FluentTitleBarButton final : public TransparentToolButton {
public:
  using TransparentToolButton::TransparentToolButton;

  void setSystemIcon(QStyle::StandardPixmap Icon) {
    SystemIcon = Icon;
    HasSystemIcon = true;
    setIcon(style()->standardIcon(Icon));
  }

protected:
  void drawIcon(QPainter *Painter, const QRectF &Rect,
                Fluent::ThemeMode ThemeMode = Fluent::ThemeMode::AUTO) override {
    if (!HasSystemIcon) {
      TransparentToolButton::drawIcon(Painter, Rect, ThemeMode);
      return;
    }
    QPixmap Pixmap = style()->standardIcon(SystemIcon).pixmap(iconSize());
    QPainter Tint(&Pixmap);
    Tint.setCompositionMode(QPainter::CompositionMode_SourceIn);
    Tint.fillRect(Pixmap.rect(), Theme::isDark() ||
                                    (objectName() == "TitleBarClose" && isHover())
                                    ? Qt::white : Qt::black);
    Tint.end();
    Painter->drawPixmap(Rect, Pixmap, Pixmap.rect());
  }

private:
  QStyle::StandardPixmap SystemIcon = QStyle::SP_TitleBarCloseButton;
  bool HasSystemIcon = false;
};

inline FluentTitleBarButton *MakeTitleBarButton(
    const QString &Name, const QString &ToolTip, int Height,
    QWidget *Parent = nullptr) {
  auto *Button = new FluentTitleBarButton(Parent);
  Button->setObjectName(Name);
  Button->setFixedSize(40, Height);
  Button->setIconSize(QSize(16, 16));
  Button->setToolTip(ToolTip);
  Button->setCursor(Qt::PointingHandCursor);
  Button->setFocusPolicy(Qt::NoFocus);
  Button->setStyleSheet(
      "QToolButton { background: transparent; border: none; padding: 0;"
      " border-radius: 0; }"
      "QToolButton:hover { background: rgba(128,128,128,32); }"
      "QToolButton:pressed { background: rgba(128,128,128,48); }"
      "QToolButton#TitleBarClose:hover { background: #C42B1C; }"
      "QToolButton#TitleBarClose:pressed { background: #A4261A; }");
  return Button;
}
