#pragma once

#include <Windows.h>
#include <QString>
#include <QStringList>

namespace HotKeyFormat {

inline QString RemovalStageName(ULONG Stage) {
  static const char* const Names[] = {
      "unspecified", "win32k image", "entry exports", "entry code pattern",
      "leave-critical-section export", "entry imports", "thread accessor import",
      "unregister wrapper", "unregister core", "delete function",
      "Win10 table/cache", "session image", "session imports", "session offsets",
      "session pointer", "session table/cache", "special window registration",
      "internal registration", "shared registration list", "GUI thread context",
      "stale snapshot", "native deletion", "EnterCrit import target",
      "leave-critical-section import target", "EnterCrit import slot",
      "leave-critical-section import slot"};
  return Stage < sizeof(Names) / sizeof(Names[0])
      ? QString::fromLatin1(Names[Stage]) : QString("unknown %1").arg(Stage);
}

inline QString VirtualKeyName(ULONG Vk) {
  if (Vk >= 'A' && Vk <= 'Z')
    return QString(QChar(static_cast<char>(Vk)));
  if (Vk >= '0' && Vk <= '9')
    return QString(QChar(static_cast<char>(Vk)));
  if (Vk >= VK_F1 && Vk <= VK_F24)
    return QString("F%1").arg(Vk - VK_F1 + 1);
  if (Vk >= VK_NUMPAD0 && Vk <= VK_NUMPAD9)
    return QString("NumPad%1").arg(Vk - VK_NUMPAD0);

  switch (Vk) {
  case VK_BACK: return "Backspace";
  case VK_TAB: return "Tab";
  case VK_RETURN: return "Enter";
  case VK_ESCAPE: return "Esc";
  case VK_SPACE: return "Space";
  case VK_PRIOR: return "PageUp";
  case VK_NEXT: return "PageDown";
  case VK_END: return "End";
  case VK_HOME: return "Home";
  case VK_LEFT: return "Left";
  case VK_UP: return "Up";
  case VK_RIGHT: return "Right";
  case VK_DOWN: return "Down";
  case VK_SNAPSHOT: return "PrintScreen";
  case VK_INSERT: return "Insert";
  case VK_DELETE: return "Delete";
  case VK_LWIN: return "Left Win";
  case VK_RWIN: return "Right Win";
  case VK_APPS: return "Menu";
  case VK_MULTIPLY: return "NumPad*";
  case VK_ADD: return "NumPad+";
  case VK_SEPARATOR: return "NumPadSeparator";
  case VK_SUBTRACT: return "NumPad-";
  case VK_DECIMAL: return "NumPadDecimal";
  case VK_DIVIDE: return "NumPad/";
  case VK_NUMLOCK: return "NumLock";
  case VK_SCROLL: return "ScrollLock";
  case VK_CAPITAL: return "CapsLock";
  case VK_PAUSE: return "Pause";
  case VK_BROWSER_BACK: return "BrowserBack";
  case VK_BROWSER_FORWARD: return "BrowserForward";
  case VK_BROWSER_REFRESH: return "BrowserRefresh";
  case VK_BROWSER_HOME: return "BrowserHome";
  case VK_VOLUME_MUTE: return "VolumeMute";
  case VK_VOLUME_DOWN: return "VolumeDown";
  case VK_VOLUME_UP: return "VolumeUp";
  case VK_MEDIA_NEXT_TRACK: return "MediaNext";
  case VK_MEDIA_PREV_TRACK: return "MediaPrevious";
  case VK_MEDIA_STOP: return "MediaStop";
  case VK_MEDIA_PLAY_PAUSE: return "MediaPlayPause";
  default: break;
  }

  // OEM 键随键盘布局变化；优先使用当前布局的系统键名，不硬编码美式标点。
  if (Vk <= 0xff) {
    const UINT Scan = MapVirtualKeyW(Vk, MAPVK_VK_TO_VSC_EX);
    if (Scan) {
      const LONG KeyInfo = static_cast<LONG>(((Scan & 0xffu) << 16) |
                                              ((Scan & 0xff00u) ? (1u << 24) : 0u));
      WCHAR Name[64] = {};
      if (GetKeyNameTextW(KeyInfo, Name, 64) > 0)
        return QString::fromWCharArray(Name);
    }
  }
  return QString("VK 0x%1").arg(Vk, 2, 16, QLatin1Char('0')).toUpper();
}

inline QString ModifierName(ULONG Modifiers) {
  QStringList Parts;
  if (Modifiers & MOD_CONTROL) Parts << "Ctrl";
  if (Modifiers & MOD_ALT) Parts << "Alt";
  if (Modifiers & MOD_SHIFT) Parts << "Shift";
  if (Modifiers & MOD_WIN) Parts << "Win";
  return Parts.join(" + ");
}

inline QString FlagsName(ULONG Flags) {
  QStringList Parts;
  if (Flags & MOD_NOREPEAT) Parts << "NoRepeat";
  const ULONG Internal = Flags & ~static_cast<ULONG>(MOD_NOREPEAT);
  if (Internal)
    Parts << QString("Internal 0x%1")
                 .arg(QString::number(Internal, 16).rightJustified(4, QLatin1Char('0')).toUpper());
  return Parts.join(", ");
}

} // namespace HotKeyFormat
