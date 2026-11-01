#pragma once
// ============================================================
// 25 个控制台页面工厂。
// ------------------------------------------------------------
// 索引与 AegisNT::PageDefinitions() / CreatePageBody 完全一致；
// shell 启动时校验 Title() 与注册表标题相符，防止两张表漂移。
// ============================================================

#include "TuiWidgets.h"

#include <memory>

namespace AegisNT::Tui {

using PageFactory = std::unique_ptr<TuiPage> (*)(int Index);

std::unique_ptr<TuiPage> MakeInformationPage(int Index);
std::unique_ptr<TuiPage> MakeTaskPage(int Index);
std::unique_ptr<TuiPage> MakeMonitorPage(int Index);
std::unique_ptr<TuiPage> MakeRegistryPage(int Index);
std::unique_ptr<TuiPage> MakeFilePage(int Index);
std::unique_ptr<TuiPage> MakeWindowPage(int Index);
std::unique_ptr<TuiPage> MakeDriverPage(int Index);
std::unique_ptr<TuiPage> MakeMemoryPage(int Index);
std::unique_ptr<TuiPage> MakeTablePage(int Index);
std::unique_ptr<TuiPage> MakeCallbackPage(int Index);
std::unique_ptr<TuiPage> MakePayloadPage(int Index);
std::unique_ptr<TuiPage> MakeModuleRunPage(int Index);
std::unique_ptr<TuiPage> MakeModuleManagerPage(int Index);
std::unique_ptr<TuiPage> MakeConsolePage(int Index);
std::unique_ptr<TuiPage> MakeChatPage(int Index);
std::unique_ptr<TuiPage> MakeSettingsPage(int Index);
std::unique_ptr<TuiPage> MakeKernelInspectorPage(int Index);
std::unique_ptr<TuiPage> MakeServicePage(int Index);
std::unique_ptr<TuiPage> MakeNetworkPage(int Index);
std::unique_ptr<TuiPage> MakeSnapshotPage(int Index);
std::unique_ptr<TuiPage> MakeDiskPage(int Index);
std::unique_ptr<TuiPage> MakeKernelResearchPage(int Index);
std::unique_ptr<TuiPage> MakeHookPage(int Index);
std::unique_ptr<TuiPage> MakeAccountPage(int Index);
std::unique_ptr<TuiPage> MakeHotKeysPage(int Index);

// 0..24；越界返回 nullptr。
PageFactory PageFactoryFor(int Index);

// 与 PageDefinitions() 的标题一致性自检（启动时调用一次）。
void ValidatePageRegistry();

} // namespace AegisNT::Tui
