#pragma once
// ============================================================
// 控制台通用控件：表格模型、文本对话框执行器、格式化工具。
// ------------------------------------------------------------
// 仅数据 + 纯文本输出；不碰 Qt 控件，不直接调驱动。
// 25 个页面共享同一套行式交互，保证行为一致。
// ============================================================

#include "TuiPlatform.h"
#include "TuiStyle.h"

#include <functional>
#include <string>
#include <vector>

namespace AegisNT::Tui {

// ------------------------------------------------------------
// 表格
// ------------------------------------------------------------

enum class TuiRowKind { Normal, Directory };
struct TuiRow {
  std::vector<std::string> Cells;
  std::string Detail; // 详情（空则由 Cells 拼）
  TuiRowKind Kind = TuiRowKind::Normal;
  bool Hidden = false;
};

struct TuiTable {
  std::vector<std::string> Headers;
  std::vector<TuiRow> Rows;      // 原始数据（页面顺序）
  std::vector<int> Visible;      // Filter 后的行索引
  std::string Filter;            // 大小写不敏感子串，匹配整行拼接
  std::vector<int> ColumnWidths; // Rebuild() 填充
  std::vector<bool> RightAlign;  // 数值列右对齐
  int Selected = 0;              // Visible 下标
  int Scroll = 0;
  int HScroll = 0;
  bool MultiSelect = false;
  std::vector<int> Marked; // 原始行索引

  void Rebuild();
  const TuiRow *Current() const;
  int CurrentRowIndex() const; // 原始行索引，-1 表示无
  void CopyCurrentToClipboard() const;
};

// 把表格渲染成 ASCII 文本（`show` 的唯一输出通道）：
// +---+ 分隔线、按 RightAlign 对齐、列宽上限 60 并截断补 "…"。
// MaxRows > 0 时只输出前 MaxRows 行，并追加剩余行数提示。
std::string TuiTableToText(const TuiTable &Table, int MaxRows);

struct TuiTableView {
  static constexpr int PageSize = 20;
  TuiTable Snapshot;
  bool Valid = false;
  int Page = 1;
  bool All = false;
  void Capture(const TuiTable &Table);
  int PageCount() const;
  bool SetPage(int Number);
  const TuiRow *RowAt(int Number) const;
  std::string Render(int Columns = 0) const;
};

// Scope captures ActiveTable from legacy RenderText without altering pages.
class TuiTableCapture {
public:
  explicit TuiTableCapture(const TuiTable *Target);
  ~TuiTableCapture();
  TuiTableCapture(const TuiTableCapture &) = delete;
  TuiTableCapture &operator=(const TuiTableCapture &) = delete;
  const TuiTable *Target;
  TuiTableView View;
  static constexpr const char *Marker = "\x1e" "AEGISNT_TABLE" "\x1f";
private:
  TuiTableCapture *Previous;
};

// 打印一行的各列（Header[i]: Cell[i]），其后原样打印 Row.Detail。
void ShowSelectedRowDetails(const TuiTable &Table, const TuiRow &Row);

// ------------------------------------------------------------
// 对话框
// ------------------------------------------------------------

enum class NoticeKind { Info, Success, Warning, Error };

enum class TuiFieldKind {
  Text,
  Password,
  Multiline,
  Combo,
  Check,
  Int,
  Hex,
  ReadOnly
};

struct TuiField {
  std::string Label;
  TuiFieldKind Kind = TuiFieldKind::Text;
  std::string Value;
  std::vector<std::string> Choices;
  int Choice = 0;
  bool Checked = false;
  std::string Placeholder;
  bool ReadOnly = false;
  std::string Hint;
};

struct TuiDialog {
  std::string Title;
  std::string Body;
  std::vector<TuiField> Fields;
  std::string PrimaryLabel = "OK";
  std::string SecondaryLabel = "Cancel";
  std::function<std::string(const TuiDialog &)> Validate; // "" 通过
  std::function<void(TuiDialog &)> OnSubmit;
  std::string Error;
  int Focus = 0;
};

// 同步文本对话框执行器：Push 立即在控制台上逐字段提问，结束后调用
// OnSubmit。没有浮层、没有帧循环，因此 Empty() 恒为 true。
class TuiDialogStack {
public:
  void Push(TuiDialog Dialog);
  void PushMessage(const std::string &Title, const std::string &Text,
                   NoticeKind Kind);
  bool Empty() const { return true; }
  void Notice(const std::string &Text, NoticeKind Kind);
  void Tick() {} // 兼容旧调用点：通知不再过期
  std::string NoticeLine() const { return {}; }
  bool ErrorsAreModal = false;

private:
  bool RenderFieldInput(TuiField &Field);
};

// 便捷封装：确认框 / 文本输入 / 只读详情。
void ConfirmDialog(TuiDialogStack &Stack, const std::string &Title,
                   const std::string &Text, std::function<void()> OnYes,
                   std::string YesLabel = "Yes", std::string NoLabel = "No",
                   std::string Id = {});
void PromptTextDialog(TuiDialogStack &Stack, const std::string &Title,
                      const std::string &Label, const std::string &Initial,
                      std::function<void(std::string)> OnSubmit,
                      std::string Hint = {});
void DetailDialog(TuiDialogStack &Stack, const std::string &Title,
                  const std::vector<TuiRow> &Rows);

// ------------------------------------------------------------
// 页面 / 命令
// ------------------------------------------------------------

struct TuiCommand {
  std::string Name;
  std::string Usage;
  std::function<void(std::vector<std::string>)> Handler;
};

struct TuiPage {
  virtual ~TuiPage() = default;
  virtual std::string Title() const = 0;
  // `use <page>` 时打印的副标题；也是 `show` 清单里的一列。
  virtual std::string Subtitle() const { return {}; }
  virtual std::string PromptLocationPath() const { return {}; }
  // shell 在 `use` 与 `refresh` 时调用：重新拉一次数据。
  virtual void OnEnter() {}
  virtual void OnTick(int64_t NowMs) { (void)NowMs; }
  // `show` 的输出：刷新数据后渲染 ASCII 表 + 该页说明行。
  virtual std::string RenderText() = 0;
  // 供 `detail <n>` / `filter` 使用；无表格的页返回 nullptr。
  virtual TuiTable *ActiveTable() { return nullptr; }

  // 由 shell 在页面创建时注入。
  TuiDialogStack *Dialogs = nullptr;
  std::vector<TuiCommand> OwnedCommands;
  std::vector<TuiCommand> &CommandsStorage() { return OwnedCommands; }
  std::vector<TuiCommand> *Commands = &OwnedCommands;
  std::string *Status = nullptr;
  std::string Filter;
  bool ReadOnlyMode = false; // 未登录时 Account/Chat 等页只读

  void Notify(const std::string &Text, NoticeKind Kind) {
    if (Dialogs)
      Dialogs->Notice(Text, Kind);
  }
  void SetStatus(const std::string &Text) {
    if (Status)
      *Status = Text;
  }
};

bool ParseCommandLine(const std::string &Line, std::vector<std::string> &Args,
                      std::string &Error);
void EraseLastUtf8(std::string &Text);

// ------------------------------------------------------------
// 杂项
// ------------------------------------------------------------

namespace TuiClipboard {
void Set(const std::string &Text);
} // namespace TuiClipboard

// "48 8B 05"、"0x48,0x8b" 等格式；失败时返回 false 并写 ErrorText。
bool ParseHexBytes(const std::string &Text, std::vector<unsigned char> &Bytes,
                   std::string *ErrorText = nullptr);

// 16 字节/行，绝对偏移 %012X，第 8 字节后加间隔，右侧 |ascii|。
std::string FormatHexAscii(const std::vector<unsigned char> &Buffer,
                           uint64_t BaseOffset);

// 小写化 / 去空白 / 前缀匹配等页面共用的小工具。
std::string LowerAscii(std::string Text);
std::string UpperAscii(std::string Text);
std::string TrimAscii(const std::string &Text);
bool StartsWithCi(const std::string &Text, const std::string &Prefix);

// 按控制台宽度折行（取不到宽度时按 80 列）。
std::vector<std::string> WrapText(const std::string &Text, int Width,
                                  const std::string &Indent = {});

} // namespace AegisNT::Tui
