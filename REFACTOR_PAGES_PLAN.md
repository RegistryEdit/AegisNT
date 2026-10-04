# AegisNT 批量页面重构计划

## 目标
将所有 25+ 个页面重构为使用新架构

## 页面清单

### 优先级 1：简单页面（先行重构）
1. ✅ ModuleRunPage - 已完成（示例）
2. RegistryPage - 注册表保护
3. FilePage - 文件保护
4. ServicePage - 服务管理
5. CallbackPage - 回调管理
6. DiskPage - 磁盘保护

### 优先级 2：中等复杂度页面
7. DriverPage - 驱动管理
8. WindowPage - 窗口管理
9. MemoryPage - 内存操作
10. HookLabPage - Hook 实验室
11. HandleLabPage - 句柄实验室
12. SnapshotLabPage - 快照实验室
13. HotKeysPage - 热键管理

### 优先级 3：复杂页面
14. TaskManagerPage - 任务管理器（需拆分）
15. KernelInspectorPage - 内核检查器（需拆分）
16. MonitorPage - 进程监控
17. TablePage - 系统表查看
18. NetworkPage - 网络管理

### 优先级 4：辅助页面
19. PayloadPage - Payload 生成
20. ConsolePage - 控制台
21. ChatPage - 聊天
22. AccountPage - 账户
23. SettingsPage - 设置
24. ModuleManagerPage - 模块管理
25. InformationPage - 系统信息

## 重构模板

每个页面统一使用以下模板：

```cpp
// PageName.h
#pragma once
#include "../UI/Common/Base/PageBase.h"
#include "../Services/IDriverService.h"

namespace AegisNT {

class PageName : public RefreshablePageBase {
    Q_OBJECT

public:
    explicit PageName(IDriverService *service, QWidget *parent = nullptr);

protected:
    void DoRefresh() override;
    void OnRefreshComplete() override;

private:
    void InitializeUI();
    // 业务逻辑方法...
    
    // UI 组件
    QTableWidget *m_table;
    RefreshControl *m_refreshControl;
    DebouncedSearchEdit *m_searchEdit;
};

} // namespace AegisNT
```

## 批量重构策略

1. **第一批**（今天）：6 个简单页面
2. **第二批**（明天）：7 个中等页面
3. **第三批**（后天）：5 个复杂页面
4. **第四批**（最后）：7 个辅助页面

## 预期收益

- 所有页面统一架构
- 代码重复率 < 5%
- 测试覆盖率 > 70%
- 维护成本降低 80%
