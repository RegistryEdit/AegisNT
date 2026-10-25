// NT API declarations
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
// RtlNtStatusToDosError 已在 winternl.h 中声明

// ============================================================
// AegisCore 驱动的用户态调用封装（全员 inline，并入主 TU）：
// 进程/注册�?文件/回调保护、内核读写信道、句�?线程注入�?
// 内存区域与页表操作、防火墙、持久化查询等全�?IOCTL 封装�?
// 每个函数成功返回 TRUE；失败时错误码写�?G_LastAegisCoreError�?
// ============================================================
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <mutex>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "advapi32.lib")

#define IOCTL_KILL_PROCESS                                                     \
  CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROCESS_PROTECT                                              \
  CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PROCESS_PROTECT                                           \
  CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_REGISTRY_PROTECT                                             \
  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_REGISTRY_PROTECT                                          \
  CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_FILE_PROTECT                                                 \
  CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_FILE_PROTECT                                              \
  CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PPL CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PPL                                                       \
  CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_ALL_PROTECTION                                             \
  CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_OBCALLBACKS                                           \
  CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_REGISTRYCALLBACKS                                     \
  CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_FILTERS                                               \
  CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS                                                   \
  CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_CALLBACK_BY_ADDRESS                                       \
  CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PPL                                                        \
  CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_CRITICAL                                                     \
  CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_CRITICAL                                                  \
  CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS                                                     \
  CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_PROCESS                                                   \
  CTL_CODE(0x8000, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FORCE_DELETE_FILE                                                \
  CTL_CODE(0x8000, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADJUST_PRIVILEGES                                                \
  CTL_CODE(0x8000, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUEUE_APC                                                        \
  CTL_CODE(0x8000, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PROCESSES                                                   \
  CTL_CODE(0x8000, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_APC                                                      \
  CTL_CODE(0x8000, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_APC                                                       \
  CTL_CODE(0x8000, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN                                                      \
  CTL_CODE(0x8000, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LAUNCH_AS                                                        \
  CTL_CODE(0x8000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY                                                      \
  CTL_CODE(0x8000, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY                                                     \
  CTL_CODE(0x8000, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_SYSTEM_TABLES                                              \
  CTL_CODE(0x8000, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_SYSTEM_TABLE_ENTRIES                                        \
  CTL_CODE(0x8000, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_DRIVERS                                                     \
  CTL_CODE(0x8000, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOAD_DRIVER                                                      \
  CTL_CODE(0x8000, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER                                                    \
  CTL_CODE(0x8000, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PIDDB_CACHE                                                 \
  CTL_CODE(0x8000, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_HAL_DISPATCH                                                \
  CTL_CODE(0x8000, 0x876, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PREVIOUS_MODE                                                \
  CTL_CODE(0x8000, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_CAPABILITIES                                            \
  CTL_CODE(0x8000, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PROCESS                                                 \
  CTL_CODE(0x8000, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_THREADS                                                  \
  CTL_CODE(0x8000, 0x82E, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_HANDLES                                                  \
  CTL_CODE(0x8000, 0x82F, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MODULES                                                  \
  CTL_CODE(0x8000, 0x830, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MEMORY                                                   \
  CTL_CODE(0x8000, 0x831, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_MEMORY                                                  \
  CTL_CODE(0x8000, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_BIG_POOL                                                 \
  CTL_CODE(0x8000, 0x833, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_OBJECTS                                                  \
  CTL_CODE(0x8000, 0x834, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_KERNEL_MODULES                                           \
  CTL_CODE(0x8000, 0x835, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_DRIVER                                                  \
  CTL_CODE(0x8000, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MINIFILTERS                                              \
  CTL_CODE(0x8000, 0x837, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_WFP                                                      \
  CTL_CODE(0x8000, 0x838, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_NDIS                                                     \
  CTL_CODE(0x8000, 0x839, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_SECURITY                                                \
  CTL_CODE(0x8000, 0x83A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TERMINATE_THREAD                                                 \
  CTL_CODE(0x8000, 0x83B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNEL_READ_MEMORY                                               \
  CTL_CODE(0x8000, 0x83C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNEL_WRITE_MEMORY                                              \
  CTL_CODE(0x8000, 0x83D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_DSE                                                      \
  CTL_CODE(0x8000, 0x83E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESTORE_DSE                                                      \
  CTL_CODE(0x8000, 0x83F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DLL_INJECT_APC                                                   \
  CTL_CODE(0x8000, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DLL_INJECT_THREAD                                                \
  CTL_CODE(0x8000, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_DEBUG                                                     \
  CTL_CODE(0x8000, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_DEBUG                                                    \
  CTL_CODE(0x8000, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_DEBUG_STATE                                                \
  CTL_CODE(0x8000, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_WINDOWS                                                     \
  CTL_CODE(0x8000, 0x845, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDOW_OPERATION                                                 \
  CTL_CODE(0x8000, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_COMMAND_LINE                                                 \
  CTL_CODE(0x8000, 0x847, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SERVICE_OPERATION                                                \
  CTL_CODE(0x8000, 0x848, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REG_OPERATION                                                    \
  CTL_CODE(0x8000, 0x849, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SESSION_OPERATION                                                \
  CTL_CODE(0x8000, 0x84A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MITIGATION_QUERY                                                 \
  CTL_CODE(0x8000, 0x84B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MITIGATION_SET                                                   \
  CTL_CODE(0x8000, 0x84C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_SYNC_OBJECTS                                                \
  CTL_CODE(0x8000, 0x84D, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_OPERATION                                               \
  CTL_CODE(0x8000, 0x84E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_FIREWALL_RULES                                              \
  CTL_CODE(0x8000, 0x87E, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define FIREWALL_OP_ADD      1u
#define FIREWALL_OP_REMOVE   2u
#define FIREWALL_OP_CLEAR    3u

#define FIREWALL_ACTION_BLOCK    0u
#define FIREWALL_ACTION_PERMIT   1u

#define FIREWALL_DIRECTION_OUT_V4  0u
#define FIREWALL_DIRECTION_OUT_V6  1u
#define FIREWALL_DIRECTION_IN_V4   2u
#define FIREWALL_DIRECTION_IN_V6   3u

/* FIREWALL_OPERATION_INPUT 的方�?协议族掩码；0 表示"不限"(双向)�?*/
#define FIREWALL_DIRBIT_OUT       1u
#define FIREWALL_DIRBIT_IN        2u
#define FIREWALL_FAMILYBIT_V4     1u
#define FIREWALL_FAMILYBIT_V6     2u

#define FIREWALL_RULE_MAX_ENTRIES 128u
#define IOCTL_ADD_WINDOW_PROTECT                                               \
  CTL_CODE(0x8000, 0x84F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_WINDOW_PROTECT                                            \
  CTL_CODE(0x8000, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_INJECTION_PROTECTION                                         \
  CTL_CODE(0x8000, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_INJECTION_PROTECTION                                      \
  CTL_CODE(0x8000, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_CLOSE                                                     \
  CTL_CODE(0x8000, 0x853, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_DOWNGRADE                                                 \
  CTL_CODE(0x8000, 0x854, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_DUP_DOWNGRADE                                             \
  CTL_CODE(0x8000, 0x855, METHOD_BUFFERED, FILE_ANY_ACCESS)
 #define IOCTL_DISABLE_PATCHGUARD                                               \
  CTL_CODE(0x8000, 0x856, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PATCHGUARD                                                 \
  CTL_CODE(0x8000, 0x858, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_PATCHGUARD_INTERCEPTION                                   \
  CTL_CODE(0x8000, 0x894, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PATCHGUARD_KPRCB                                           \
  CTL_CODE(0x8000, 0x895, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* 0x857 原为 IOCTL_RESTORE_PATCHGUARD，该功能已移除。编号不复用�?*/
#define IOCTL_QUERY_DSE                                                        \
  CTL_CODE(0x8000, 0x859, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_IDT_LIMIT                                                    \
  CTL_CODE(0x8000, 0x85A, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* 取消�?PatchGuard 相关�?DPC：枚举全�?DPC 队列并解码，找出
   DeferredContext 为非规范指针、且 DeferredRoutine 落在 ntoskrnl 内的
   条目后将其从队列摘除�?*/
#define IOCTL_CANCEL_PATCHGUARD_DPC                                            \
  CTL_CODE(0x8000, 0x88C, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* PPN 路径（第三路径）：把 PG 校验例程所在可执行页置 NX �?Hook #PF�?
   Output �?PG_CONTROL_OUTPUT�?*/
#define IOCTL_ENABLE_PPN                                                       \
  CTL_CODE(0x8000, 0x88D, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* PPN rollback: restore all IDT gates and target PTEs. */
#define IOCTL_DISABLE_PPN                                                      \
  CTL_CODE(0x8000, 0x896, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* 取消 PG 相关 APC：遍历所有内核线程的 KernelMode APC 队列，摘�?
   KernelRoutine == ntoskrnl!KiDispatchCallout �?RundownRoutine == NULL
   的条目。Output �?APC_CANCEL_OUTPUT�?*/
#define IOCTL_CANCEL_PATCHGUARD_APC                                            \
  CTL_CODE(0x8000, 0x88E, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* 列出所有内核 APC（含普通条目）：只读查询，不摘链。Output 为 APC_CANCEL_OUTPUT。 */
#define IOCTL_ENUM_APC                                                        \
  CTL_CODE(0x8000, 0x88F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APC_CAPTURE_CTL                                                 \
  CTL_CODE(0x8000, 0x890, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_APC_CAPTURE_READ                                                \
  CTL_CODE(0x8000, 0x891, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_TEST_APC                                                 \
  CTL_CODE(0x8000, 0x892, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_ADVANCED                                                \
  CTL_CODE(0x8000, 0x85C, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ADVANCED_OPERATION                                            \
  CTL_CODE(0x8000, 0x85D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_HIJACK_CONTEXT                                            \
  CTL_CODE(0x8000, 0x85E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_HIJACK_TRAPFRAME                                          \
  CTL_CODE(0x8000, 0x85F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_REMOTE_CALL                                               \
  CTL_CODE(0x8000, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_SHELLCODE_INJECT                                          \
  CTL_CODE(0x8000, 0x861, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_INJECT_AND_HIJACK                                         \
  CTL_CODE(0x8000, 0x862, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_QUERY_CAPABILITIES                                          \
  CTL_CODE(0x8000, 0x863, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_ENUM                                                        \
  CTL_CODE(0x8000, 0x864, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_INSTALL                                                     \
  CTL_CODE(0x8000, 0x865, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_ENABLE                                                      \
  CTL_CODE(0x8000, 0x866, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_DISABLE                                                     \
  CTL_CODE(0x8000, 0x867, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_REMOVE                                                      \
  CTL_CODE(0x8000, 0x868, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_RESTORE_ALL                                                 \
  CTL_CODE(0x8000, 0x869, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOOK_VERIFY                                                      \
  CTL_CODE(0x8000, 0x86A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TERMINATE_PROCESS_THREADS                                       \
  CTL_CODE(0x8000, 0x86B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TERMINATE_PROCESS_MEMORY                                         \
  CTL_CODE(0x8000, 0x86C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_DPC                                                         \
  CTL_CODE(0x8000, 0x883, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_DPC                                                       \
  CTL_CODE(0x8000, 0x884, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PIDDB_ENTRY                                               \
  CTL_CODE(0x8000, 0x885, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_HOTKEYS                                                     \
  CTL_CODE(0x8000, 0x86D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_THREADS_ALL                                                \
  CTL_CODE(0x8000, 0x886, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_SUSPEND                                                  \
  CTL_CODE(0x8000, 0x887, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREAD_RESUME                                                   \
  CTL_CODE(0x8000, 0x888, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_THREAD_PREVIOUS_MODE                                        \
  CTL_CODE(0x8000, 0x889, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_THREAD_APC_QUEUEABLE                                        \
  CTL_CODE(0x8000, 0x88A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROCESS_CREATE_BLOCK                                          \
  CTL_CODE(0x8000, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PROCESS_CREATE_BLOCK                                       \
  CTL_CODE(0x8000, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PROCESS_CREATE_BLOCK                                         \
  CTL_CODE(0x8000, 0x872, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_SCAN                                                      \
  CTL_CODE(0x8000, 0x873, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ETW_PROVIDER_OPERATION                                            \
  CTL_CODE(0x8000, 0x877, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ETW_QUERY_PROVIDERS                                               \
  CTL_CODE(0x8000, 0x878, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MSR_OPERATION                                                     \
  CTL_CODE(0x8000, 0x879, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCESS_DISGUISE                                                  \
  CTL_CODE(0x8000, 0x87A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_DRIVER                                                       \
  CTL_CODE(0x8000, 0x87B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_DRIVER_CID                                                   \
  CTL_CODE(0x8000, 0x875, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS_CID                                                  \
  CTL_CODE(0x8000, 0x874, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PROCESS_ALIVE                                              \
  CTL_CODE(0x8000, 0x893, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HOOK_PROTOCOL_VERSION 1u
#define HOOK_TARGET_DRIVER_DISPATCH 1u
#define HOOK_TARGET_FAST_IO 2u
#define HOOK_TARGET_SSDT 3u
#define HOOK_TARGET_IDT 4u
#define HOOK_TARGET_INLINE 5u
#define HOOK_TARGET_VT_EPT 6u
#define HOOK_OP_INSTALL 1u
#define HOOK_OP_ENABLE 2u
#define HOOK_OP_DISABLE 3u
#define HOOK_OP_REMOVE 4u
#define HOOK_OP_VERIFY 5u
#define HOOK_OP_RESTORE_ALL 6u
#define HOOK_STATE_EMPTY 0u
#define HOOK_STATE_PREPARED 1u
#define HOOK_STATE_ACTIVE 2u
#define HOOK_STATE_DISABLED 3u
#define HOOK_STATE_RESTORED 4u
#define HOOK_STATE_FAILED 5u
#define HOOK_FLAG_SHADOW_SSDT 0x00000001u
#define HOOK_FLAG_PROXY_REQUIRED 0x00000002u
#define HOOK_FAST_IO_CHECK_IF_POSSIBLE 0u

typedef struct _HOOK_CAPABILITIES_OUTPUT {
  ULONG Size;
  ULONG Version;
  ULONG SupportedTargets;
  ULONG SupportedOperations;
  ULONG MaxHooks;
  ULONG ActiveHooks;
  ULONG Flags;
  LONG LastStatus;
} HOOK_CAPABILITIES_OUTPUT, *PHOOK_CAPABILITIES_OUTPUT;

typedef struct _HOOK_REQUEST {
  ULONG Size;
  ULONG Version;
  ULONG Operation;
  ULONG TargetKind;
  ULONG HookId;
  ULONG MajorFunction;
  ULONG TableIndex;
  ULONG Vector;
  ULONG64 TargetAddress;
  ULONG64 ProxyAddress;
  WCHAR ModuleName[128];
  WCHAR DriverName[128];
  ULONG Flags;
  ULONG Reserved;
} HOOK_REQUEST, *PHOOK_REQUEST;

typedef struct _HOOK_RECORD {
  ULONG Size;
  ULONG Version;
  ULONG HookId;
  ULONG State;
  ULONG TargetKind;
  ULONG MajorFunction;
  ULONG TableIndex;
  ULONG Vector;
  ULONG64 TargetAddress;
  ULONG64 OriginalAddress;
  ULONG64 ProxyAddress;
  ULONG64 HitCount;
  ULONG ActiveCalls;
  LONG Status;
  ULONG Flags;
  WCHAR ModuleName[128];
  WCHAR DriverName[128];
  WCHAR Detail[256];
} HOOK_RECORD, *PHOOK_RECORD;

typedef struct _HOOK_ENUM_OUTPUT {
  ULONG Size;
  ULONG Version;
  ULONG Count;
  ULONG Capacity;
  HOOK_RECORD Records[1];
} HOOK_ENUM_OUTPUT, *PHOOK_ENUM_OUTPUT;

#define ADVANCED_KIND_PTE 1u
#define ADVANCED_KIND_VAD 2u
#define ADVANCED_KIND_THREAD_STACK 3u
#define ADVANCED_KIND_SYSTEM_TABLE 4u
#define ADVANCED_KIND_DRIVER_DISPATCH 5u
#define ADVANCED_KIND_DRIVER_UNLOAD 6u
#define ADVANCED_KIND_HARDWARE 7u
#define ADVANCED_KIND_FIRMWARE 8u
#define ADVANCED_OP_CAPTURE 1u
#define ADVANCED_OP_APPLY 2u
#define ADVANCED_OP_ROLLBACK 3u
#define IOCTL_QUERY_EPROCESS                                                \
  CTL_CODE(0x8000, 0x85B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CALLBACK_TYPE_OB_PROCESS 0
#define CALLBACK_TYPE_OB_THREAD 1
#define CALLBACK_TYPE_REGISTRY 2
#define CALLBACK_TYPE_FLT_PRE_CREATE 3
#define CALLBACK_TYPE_FLT_PRE_SET_INFORMATION 4
#define CALLBACK_TYPE_FLT_PRE_WRITE 5
#define CALLBACK_TYPE_FLT_PRE_READ 12
#define CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION 13
#define CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL 14
#define CALLBACK_TYPE_FLT_PRE_CLEANUP 15
#define CALLBACK_TYPE_FLT_PRE_CLOSE 16
#define CALLBACK_TYPE_FLT_POST_CREATE 17
#define CALLBACK_TYPE_FLT_POST_READ 18
#define CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION 19
#define CALLBACK_TYPE_FLT_POST_SET_INFORMATION 20
#define CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL 21
#define CALLBACK_TYPE_FLT_POST_WRITE 22
#define CALLBACK_TYPE_FLT_POST_CLEANUP 23
#define CALLBACK_TYPE_FLT_POST_CLOSE 24
#define CALLBACK_TYPE_PS_PROCESS_NOTIFY 6
#define CALLBACK_TYPE_PS_THREAD_NOTIFY 7
#define CALLBACK_TYPE_PS_IMAGE_NOTIFY 8
#define CALLBACK_TYPE_BUGCHECK 9
#define CALLBACK_TYPE_SHUTDOWN 10
#define CALLBACK_TYPE_BUGCHECK_REASON 11
#define CALLBACK_FLAG_CAN_REMOVE 0x00000001ul
typedef struct _KILL_PROCESS_INPUT {
  ULONG ProcessId;
} KILL_PROCESS_INPUT;

typedef struct _TERMINATE_PROCESS_MEMORY_INPUT {
    ULONG ProcessId;
} TERMINATE_PROCESS_MEMORY_INPUT, * PTERMINATE_PROCESS_MEMORY_INPUT;

#define PROCESS_CREATE_BLOCK_ACTION_AUDIT   0u
#define PROCESS_CREATE_BLOCK_ACTION_BLOCK   1u
#define PROCESS_CREATE_BLOCK_MAX_ENTRIES    256u
#define PROCESS_CREATE_BLOCK_MATCH_IMAGE    0x00000001u
#define PROCESS_CREATE_BLOCK_MATCH_PARENT   0x00000002u
#define PROCESS_CREATE_BLOCK_MATCH_COMMAND  0x00000004u
#define PROCESS_CREATE_BLOCK_WHITELIST      0x00000080u
#define PROCESS_CREATE_BLOCK_OP_ADD    1u
#define PROCESS_CREATE_BLOCK_OP_REMOVE 2u
#define PROCESS_CREATE_BLOCK_OP_CLEAR  3u

typedef struct _PROCESS_CREATE_BLOCK_ENTRY {
  ULONG Index;
  ULONG Action;
  ULONG Flags;
  ULONG ParentPid;
  ULONG ProcessId;
  WCHAR ImagePattern[260];
  WCHAR CommandPattern[260];
} PROCESS_CREATE_BLOCK_ENTRY;

typedef struct _PROCESS_CREATE_BLOCK_INPUT {
  ULONG Operation;
  PROCESS_CREATE_BLOCK_ENTRY Entry;
} PROCESS_CREATE_BLOCK_INPUT;

typedef struct _PROCESS_CREATE_BLOCK_OUTPUT {
  ULONG Count;
  ULONG TotalCount;
  ULONG Enabled;
  PROCESS_CREATE_BLOCK_ENTRY Entries[PROCESS_CREATE_BLOCK_MAX_ENTRIES];
} PROCESS_CREATE_BLOCK_OUTPUT;

static_assert(sizeof(PROCESS_CREATE_BLOCK_ENTRY) == 1060,
              "Process create block entry ABI mismatch");
static_assert(sizeof(PROCESS_CREATE_BLOCK_INPUT) == 1064,
              "Process create block input ABI mismatch");
static_assert(sizeof(PROCESS_CREATE_BLOCK_OUTPUT) == 271372,
              "Process create block output ABI mismatch");

// ---- 驱动映像加载阻断 (IOCTL 0x87C-0x87D) ----
#define IOCTL_DRIVER_IMAGE_BLOCK_OP                                             \
  CTL_CODE(0x8000, 0x87C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_DRIVER_IMAGE_BLOCK                                           \
  CTL_CODE(0x8000, 0x87D, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define DRIVER_IMAGE_BLOCK_OP_ADD    1u
#define DRIVER_IMAGE_BLOCK_OP_REMOVE 2u
#define DRIVER_IMAGE_BLOCK_OP_CLEAR  3u
#define DRIVER_IMAGE_BLOCK_MAX_ENTRIES 128u

typedef struct _DRIVER_IMAGE_BLOCK_ENTRY {
  ULONG Index;
  ULONG Flags;
  WCHAR ImagePattern[260];
} DRIVER_IMAGE_BLOCK_ENTRY;

typedef struct _DRIVER_IMAGE_BLOCK_INPUT {
  ULONG Operation;
  ULONG Reserved;
  DRIVER_IMAGE_BLOCK_ENTRY Entry;
} DRIVER_IMAGE_BLOCK_INPUT;

typedef struct _DRIVER_IMAGE_BLOCK_OUTPUT {
  ULONG Size;
  ULONG Count;
  ULONG TotalCount;
  ULONG Enabled;
  DRIVER_IMAGE_BLOCK_ENTRY Entries[DRIVER_IMAGE_BLOCK_MAX_ENTRIES];
} DRIVER_IMAGE_BLOCK_OUTPUT;

static_assert(sizeof(DRIVER_IMAGE_BLOCK_ENTRY) == 528,
              "Driver image block entry ABI mismatch");
static_assert(sizeof(DRIVER_IMAGE_BLOCK_INPUT) == 536,
              "Driver image block input ABI mismatch");
static_assert(sizeof(DRIVER_IMAGE_BLOCK_OUTPUT) == 67600,
              "Driver image block output ABI mismatch");

#define PROCESS_DISGUISE_MODE_CURRENT  0u
#define PROCESS_DISGUISE_MODE_CUSTOM   1u

typedef struct _PROCESS_DISGUISE_ENTRY {
  ULONG Mode;
  ULONG TargetPid;
  ULONG SourcePid;
  ULONG FakePid;
  ULONG FakeParentPid;
  WCHAR FakeImagePath[260];
} PROCESS_DISGUISE_ENTRY, *PPROCESS_DISGUISE_ENTRY;

typedef struct _PROCESS_DISGUISE_INPUT {
  PROCESS_DISGUISE_ENTRY Entry;
} PROCESS_DISGUISE_INPUT, *PPROCESS_DISGUISE_INPUT;

static_assert(sizeof(PROCESS_DISGUISE_ENTRY) == 540,
              "Process disguise entry ABI mismatch");
static_assert(sizeof(PROCESS_DISGUISE_INPUT) == 540,
              "Process disguise input ABI mismatch");

constexpr ULONG ROOTKIT_SCAN_KIND_HIDDEN_MODULES = 1u;
constexpr ULONG ROOTKIT_SCAN_KIND_TEXT_INTEGRITY = 2u;
constexpr ULONG ROOTKIT_SCAN_KIND_CALLBACKS = 3u;
constexpr ULONG ROOTKIT_SCAN_KIND_ALL = 4u;
constexpr ULONG ROOTKIT_SCAN_FLAG_REPORT_ONLY = 0x00000001u;
constexpr ULONG ROOTKIT_SCAN_FLAG_INCLUDE_DRIVERS = 0x00000002u;
constexpr ULONG ROOTKIT_SCAN_MAX_RECORDS = 512u;

typedef struct _ROOTKIT_SCAN_INPUT {
  ULONG Size;
  ULONG Version;
  ULONG Kind;
  ULONG Flags;
} ROOTKIT_SCAN_INPUT;

typedef struct _ROOTKIT_SCAN_RECORD {
  ULONG Kind;
  ULONG Severity;
  ULONG_PTR Address;
  ULONG_PTR Size;
  ULONG Extra;
  WCHAR ModuleName[64];
  WCHAR Detail[256];
} ROOTKIT_SCAN_RECORD;

typedef struct _ROOTKIT_SCAN_OUTPUT {
  ULONG Size;
  ULONG Version;
  NTSTATUS Status;
  ULONG Count;
  ULONG Scanned;
  ULONG Kind;
  ULONG Flags;
  ROOTKIT_SCAN_RECORD Records[ROOTKIT_SCAN_MAX_RECORDS];
} ROOTKIT_SCAN_OUTPUT;

static_assert(sizeof(ROOTKIT_SCAN_RECORD) == 672,
              "Rootkit scan record ABI mismatch");
static_assert(sizeof(ROOTKIT_SCAN_OUTPUT) == 344096,
              "Rootkit scan output ABI mismatch");

constexpr ULONG ETW_PROVIDER_OP_STOP = 0u;
constexpr ULONG ETW_PROVIDER_OP_START = 1u;
constexpr ULONG ETW_PROVIDER_OP_ENABLE = 2u;
constexpr ULONG ETW_PROVIDER_OP_DISABLE = 3u;
constexpr ULONG ETW_PROVIDER_MAX_COUNT = 5u;

typedef struct _ETW_PROVIDER_OPERATION {
  ULONG Size;
  ULONG Version;
  ULONG Operation;
  ULONG ProviderIndex;
  GUID ProviderGuid;
  ULONG64 MatchAnyKeyword;
  UCHAR Level;
  UCHAR Padding[7];
} ETW_PROVIDER_OPERATION;

typedef struct _ETW_PROVIDER_STATUS_ITEM {
  GUID ProviderGuid;
  WCHAR Name[64];
  ULONG Enabled;
  ULONG Reserved;
  ULONG64 Keywords;
  UCHAR Level;
  UCHAR Reserved2[7];
  ULONG64 EventCount;
} ETW_PROVIDER_STATUS_ITEM;

typedef struct _ETW_PROVIDER_STATUS {
  ULONG Size;
  ULONG Version;
  ULONG Count;
  ULONG SessionActive;
  ULONG64 SessionHandle;
  ETW_PROVIDER_STATUS_ITEM Providers[ETW_PROVIDER_MAX_COUNT];
} ETW_PROVIDER_STATUS;

static_assert(sizeof(ETW_PROVIDER_OPERATION) == 48,
              "ETW provider operation ABI mismatch");
static_assert(sizeof(ETW_PROVIDER_STATUS_ITEM) == 176,
              "ETW provider status item ABI mismatch");
static_assert(sizeof(ETW_PROVIDER_STATUS) == 904,
              "ETW provider status ABI mismatch");

constexpr ULONG MSR_OP_QUERY = 1u;
constexpr ULONG MSR_OP_ENABLE_WATCH = 2u;
constexpr ULONG MSR_OP_DISABLE_WATCH = 3u;
constexpr ULONG MSR_WATCH_COUNT = 8u;

typedef struct _MSR_OPERATION_INPUT {
  ULONG Size;
  ULONG Version;
  ULONG Operation;
  ULONG Reserved;
} MSR_OPERATION_INPUT;

typedef struct _MSR_WATCH_VALUE {
  ULONG Register;
  ULONG Changed;
  ULONG64 Value;
  ULONG64 Baseline;
  WCHAR Name[32];
} MSR_WATCH_VALUE;

typedef struct _MSR_QUERY_OUTPUT {
  ULONG Size;
  ULONG Version;
  ULONG WatchActive;
  ULONG LstarHooked;
  ULONG LstarUnknown;
  ULONG Reserved;
  ULONG64 KiSystemCall64;
  ULONG64 LstarValue;
  ULONG64 EferValue;
  ULONG64 StarValue;
  ULONG64 FmaskValue;
  ULONG64 SysenterEip;
  MSR_WATCH_VALUE WatchValues[MSR_WATCH_COUNT];
} MSR_QUERY_OUTPUT;

static_assert(sizeof(MSR_OPERATION_INPUT) == 16,
              "MSR operation input ABI mismatch");
static_assert(sizeof(MSR_WATCH_VALUE) == 88,
              "MSR watch value ABI mismatch");
static_assert(sizeof(MSR_QUERY_OUTPUT) == 776,
              "MSR query output ABI mismatch");

typedef struct _PROCESS_PROTECT_INPUT {
  ULONG ProcessId;
} PROCESS_PROTECT_INPUT;

typedef struct _REGISTRY_PROTECT_INPUT {
  WCHAR KeyPath[256];
} REGISTRY_PROTECT_INPUT;

typedef struct _FILE_PROTECT_INPUT {
  WCHAR FilePath[260];
} FILE_PROTECT_INPUT;

typedef struct _PPL_CONTROL_INPUT {
  ULONG ProcessId;
  UCHAR ProtectionType;
  UCHAR ProtectionSigner;
  BOOLEAN Audit;
  BOOLEAN RemoveProtection;
} PPL_CONTROL_INPUT;

typedef struct _CALLBACK_ENTRY {
  ULONG Type;
  ULONG Flags;
  ULONG_PTR Address;
  WCHAR ModuleName[64];
  WCHAR SourceName[64];
} CALLBACK_ENTRY, *PCALLBACK_ENTRY;

typedef struct _CALLBACK_ENUM_OUTPUT {
  ULONG Count;
  CALLBACK_ENTRY Entries[1];
} CALLBACK_ENUM_OUTPUT, *PCALLBACK_ENUM_OUTPUT;

typedef struct _CALLBACK_REMOVE_INPUT {
  ULONG Type;
  ULONG Flags;
  ULONG_PTR Address;
} CALLBACK_REMOVE_INPUT, *PCALLBACK_REMOVE_INPUT;

typedef struct _PPL_QUERY_INPUT {
  ULONG ProcessId;
} PPL_QUERY_INPUT;

typedef struct _PPL_QUERY_OUTPUT {
  ULONG ProcessId;
  UCHAR ProtectionType;
  UCHAR ProtectionSigner;
  BOOLEAN Audit;
  BOOLEAN IsProtected;
  UCHAR RawLevel;
} PPL_QUERY_OUTPUT;

typedef struct _CRITICAL_PROCESS_INPUT {
  ULONG ProcessId;
  UCHAR PreviousMode;   /* 0 = KernelMode, 1 = UserMode（与驱动 Protocol/Process.h 同步�?*/
  UCHAR _Pad[3];
} CRITICAL_PROCESS_INPUT;

typedef struct _PROCESS_ALIVE_OUTPUT {
  ULONG ProcessId;
  BOOLEAN Alive;
  UCHAR _Pad[3];
} PROCESS_ALIVE_OUTPUT;

typedef struct _FORCE_DELETE_INPUT {
  WCHAR FilePath[260];
} FORCE_DELETE_INPUT;

typedef struct _PRIVILEGE_ADJUST_INPUT {
  ULONG ProcessId;
  LUID PrivilegeLuid;
  BOOLEAN Enable;
} PRIVILEGE_ADJUST_INPUT;

typedef struct _APC_INPUT {
  ULONG ProcessId;
  ULONG ApcAction;
} APC_INPUT;

typedef struct _STEAL_TOKEN_INPUT {
  ULONG SourceProcessId;
  ULONG TargetProcessId;
} STEAL_TOKEN_INPUT;

typedef struct _TERMINATE_THREAD_INPUT {
  ULONG ProcessId;
  ULONG ThreadId;
} TERMINATE_THREAD_INPUT;

typedef struct _TERMINATE_PROCESS_THREADS_INPUT {
  ULONG ProcessId;
} TERMINATE_PROCESS_THREADS_INPUT;

typedef struct _TERMINATE_PROCESS_THREADS_OUTPUT {
  ULONG ProcessId;
  ULONG EnumeratedCount;
  ULONG TerminatedCount;
  ULONG FailedCount;
  LONG LastStatus;
} TERMINATE_PROCESS_THREADS_OUTPUT;

static_assert(sizeof(TERMINATE_PROCESS_THREADS_OUTPUT) == 20,
              "TERMINATE_PROCESS_THREADS_OUTPUT ABI mismatch");
static_assert(sizeof(TERMINATE_PROCESS_THREADS_INPUT) == 4,
              "TERMINATE_PROCESS_THREADS_INPUT ABI mismatch");

#define ACCOUNT_TYPE_SYSTEM 0
#define ACCOUNT_TYPE_TRUSTEDINSTALLER 1

typedef struct _DLL_INJECT_INPUT {
  ULONG ProcessId;
  WCHAR DllPath[260];
} DLL_INJECT_INPUT;

typedef struct _LAUNCH_AS_INPUT {
  ULONG AccountType;
  WCHAR ImagePath[260];
  ULONG ProcessId;
  ULONG ThreadId;
  ULONG ErrorCode;
} LAUNCH_AS_INPUT;

#define APC_ACTION_NOOP 0
#define APC_ACTION_TERMINATE 1
#define APC_ACTION_EXIT_THREAD 2
#define APC_ACTION_HANG 3

typedef struct _PROCESS_ENUM_ENTRY {
  ULONG ProcessId;
  ULONG ParentPid;
  ULONG ThreadCount;
  ULONG SessionId;
  BOOLEAN IsPplProtected;
  BOOLEAN IsCritical;
  BOOLEAN IsHidden;
  UCHAR PplRawLevel;
  UCHAR _Padding[3];
  ULONG_PTR ObjectAddress;
  WCHAR ImageName[16];
} PROCESS_ENUM_ENTRY, *PPROCESS_ENUM_ENTRY;

static_assert(sizeof(PROCESS_ENUM_ENTRY) == 64,
              "PROCESS_ENUM_ENTRY ABI mismatch");

typedef struct _PROCESS_ENUM_OUTPUT {
  ULONG Count;
  PROCESS_ENUM_ENTRY Entries[1];
} PROCESS_ENUM_OUTPUT, *PPROCESS_ENUM_OUTPUT;

typedef struct _MEMORY_READ_INPUT {
  ULONG ProcessId;
  ULONG_PTR Address;
  ULONG Size;
} MEMORY_READ_INPUT, *PMEMORY_READ_INPUT;

typedef struct _MEMORY_WRITE_INPUT {
  ULONG ProcessId;
  ULONG_PTR Address;
  ULONG Size;
} MEMORY_WRITE_INPUT, *PMEMORY_WRITE_INPUT;

enum KRNL_MEMRW_METHOD : ULONG {
  KrnlMemRwAuto = 0,
  KrnlMemRwMdl = 1,
  KrnlMemRwCr0 = 2,
  KrnlMemRwDirect = 3,
};

typedef struct _KERNEL_READ_INPUT {
  ULONG_PTR Address;
  ULONG Size;
  KRNL_MEMRW_METHOD Method;
} KERNEL_READ_INPUT, *PKERNEL_READ_INPUT;

typedef struct _KERNEL_WRITE_INPUT {
  ULONG_PTR Address;
  ULONG Size;
  KRNL_MEMRW_METHOD Method;
} KERNEL_WRITE_INPUT, *PKERNEL_WRITE_INPUT;

typedef struct _KERNEL_READ_OUTPUT {
  ULONG BytesRead;
  ULONG Status;
  UCHAR Data[1];
} KERNEL_READ_OUTPUT, *PKERNEL_READ_OUTPUT;

typedef struct _DSE_CONTROL_INPUT {
  ULONG Reserved;
} DSE_CONTROL_INPUT, *PDSE_CONTROL_INPUT;

typedef struct _DSE_CONTROL_OUTPUT {
  ULONG_PTR CiOptionsAddress;
  ULONG OriginalValue;
  ULONG CurrentValue;
  ULONG Status;
} DSE_CONTROL_OUTPUT, *PDSE_CONTROL_OUTPUT;

typedef struct _PG_CONTROL_OUTPUT {
  ULONG PgContextOffset;
  ULONG _Pad0;
  ULONG_PTR OriginalValue;
  ULONG_PTR CurrentValue;
  BOOLEAN IsPatched;
  UCHAR _Pad1[7];
  ULONG Status;
  /* ---- DPC 状�?----
     PatchGuard 查询会实时重跑一�?DPC 扫描（只分类不摘除），因此查询返�?
     �?DpcFound �?当前挂在队列上的 PG 嫌疑 DPC 数量"�?
     禁用操作则回填实际摘除结果�?*/
  ULONG DpcFound;     /* 当前找到�?PG 嫌疑 DPC 数量 */
  ULONG DpcScanned;   /* 扫描/解码�?DPC 总数 */
  ULONG DpcCancelled; /* 实际摘除数（仅禁用后有效�?*/
  ULONG DpcStatus;    /* 0 = 成功；非 0 �?NTSTATUS 摘要 */

  /* ---- 早期 bugcheck 拦截状态（ByePg 式主路径�?---
     该路径反汇编 ntoskrnl!KeBugCheckEx 解析 PG 相关符号，劫�?
     HalPrivateDispatchTable 建立早期 bugcheck 钩子，在 PG 校验失败触发
     bugcheck 时恢复被打断的执行流从�?吃掉"蓝屏；不修改 PG 自身状态，
     可与 KPRCB 上下文清零（辅路径）叠加�?*/
  BOOLEAN InterceptEnabled;      /* 拦截层是否已启用 */
  UCHAR _Pad2[3];
  ULONG InterceptStatus;         /* 启用结果 NTSTATUS */
  ULONG ResolveStage;            /* PG_RESOLVE_STAGE_* 位组�?*/
  ULONG HalHookMask;             /* PG_HAL_HOOK_* 位组�?*/
  ULONG HalVersion;              /* HalPrivateDispatchTable.Version */

  /* _KPRCB.Context �?KPRCB 内的**偏移**（不是地址）�?*/
  ULONG KprcbContextOffset;

  /* 解析出的关键符号**完整地址**；另配有效标志以区分"地址恰为 0"
     �?未解析出�?（旧版只回填�?32 位，页对齐地址会被误读成失败）�?*/
  ULONG64 KiHardwareTriggerAddr;
  ULONG64 KiBugCheckActiveAddr;
  ULONG64 KiFreezeExecutionLockAddr;
  BOOLEAN KiHardwareTriggerResolved;
  BOOLEAN KiBugCheckActiveResolved;
  BOOLEAN KiFreezeLockResolved;
  BOOLEAN AllCriticalResolved;

  /* ---- 拦截运行时计�?---- */
  ULONG SuppressedCount;         /* 已成功吃掉的 bugcheck 次数 */
  ULONG FreezeNotifies;          /* 收到�?processor freeze 通知次数 */
  ULONG BugCheckNotifies;        /* 收到�?bugcheck 通知次数 */
  ULONG LastBugCheckCode;        /* 最近一次处理的 bugcheck code */
  ULONG _Pad3;
  ULONG_PTR LastBugCheckRip;     /* 最近一次被打断�?RIP */

  /* ---- 辅路径审计：清零实际使用的偏移与来源 ----
     PG_OFFSET_SOURCE_DETERMINISTIC（反汇编精确解析）或
     PG_OFFSET_SOURCE_HEURISTIC（跨核一致性兜底）�?*/
  ULONG ClearOffset;             /* 本次清零实际使用�?KPRCB 偏移 */
  ULONG OffsetSource;            /* PG_OFFSET_SOURCE_* */

  /* ---- PPN 路径（第三路径）：PG 代码�?NX �?+ #PF 拦截 ---- */
  BOOLEAN PpnActive;             /* PPN 是否已启�?*/
  UCHAR _PadPpn[7];
  ULONG PpnTargetCount;          /* �?NX 化的 PG 代码页数�?*/
  ULONG PpnNxFaults;             /* 命中并处理的 NX 取指 #PF 次数 */
  ULONG PpnPassthrough;          /* #PF 透传次数 */
  ULONG PpnStatus;               /* NTSTATUS 摘要 */
  ULONG64 PpnTargetPages[4];     /* �?4 个目标页地址（诊断） */

  /* ---- APC 摘除状态（�?DPC 路径对称�?--- */
  ULONG ApcFound;                /* 当前找到�?PG 嫌疑 APC 数量 */
  ULONG ApcScanned;              /* 扫描/解码�?APC 总数 */
  ULONG ApcCancelled;            /* 实际摘除数（仅禁用后有效�?*/
  ULONG ApcStatus;               /* 0 = 成功；非 0 �?NTSTATUS 摘要 */
  ULONG CpuTotal;
  ULONG CpuAttempted;
  ULONG CpuCleared;
  ULONG CpuFailed;
  ULONG ProcessorGroupCount;
  ULONG ProcessorGroupsCovered;
  ULONG CompatibilityFlags;
  ULONG ContextConfidence;
  ULONG ContextEvidence;
  ULONG DpcHighConfidenceCount;
  ULONG DpcLowConfidenceCount;
  ULONG ApcResolverConfidence;
  ULONG ApcResolverAnchorCount;
  ULONG ApcHighConfidenceCount;
  ULONG ApcLowConfidenceCount;
} PG_CONTROL_OUTPUT, *PPG_CONTROL_OUTPUT;

/* ---- 辅路径偏移来源（PG_CONTROL_OUTPUT.OffsetSource�?--- */
#define PG_OFFSET_SOURCE_NONE 0u
#define PG_OFFSET_SOURCE_DETERMINISTIC 1u
#define PG_OFFSET_SOURCE_HEURISTIC 2u

/* ---- 解析阶段位（PG_CONTROL_OUTPUT.ResolveStage�?--- */
#define PG_RESOLVE_STAGE_KPRCB_CONTEXT 0x01u
#define PG_RESOLVE_STAGE_DEBUG_IRQL 0x02u
#define PG_RESOLVE_STAGE_HW_TRIGGER 0x04u
#define PG_RESOLVE_STAGE_BUGCHECK2 0x08u
#define PG_RESOLVE_STAGE_BUGCHECK_ACTIVE 0x10u
#define PG_RESOLVE_STAGE_FREEZE_LOCK 0x20u
#define PG_RESOLVE_STAGE_NT_BASE 0x40u

/* ---- HAL 钩子位（PG_CONTROL_OUTPUT.HalHookMask�?--- */
#define PG_HAL_HOOK_PREPARE_BUGCHECK 0x1u
#define PG_HAL_HOOK_NOTIFY_FREEZE 0x2u
#define PG_HAL_HOOK_TIMER_WATCHDOG 0x4u
#define PG_HAL_HOOK_RESTORE_HV 0x8u

/* ABI 尺寸守卫：驱动与用户态各自维护一�?PG_CONTROL_OUTPUT 定义�?
   任何一侧增删字段都会改变结构大小。此处用静态断言把期望大小钉死，
   让不一致在编译期暴露，而不是在运行时把缓冲区写坏�?*/
static_assert(sizeof(PG_CONTROL_OUTPUT) == 280,
              "PG_CONTROL_OUTPUT ABI mismatch: sync with "
              "Drivers/Ring0Core/Include/Protocol/Protect.h");

/* ============================================================
   PatchGuard DPC 取消
   ============================================================
   枚举所�?CPU �?DPC 队列并解码每�?_KDPC，筛�?
   DeferredContext 为非规范指针、且 DeferredRoutine 落在 ntoskrnl
   映像内的条目（PG 校验 DPC 的典型形态）后从队列摘除�?*/

#define DPC_CANCEL_MAX_ENTRIES 128

#define DPC_CANCEL_FLAG_TRUNCATED 0x1u    /* 样本数组已截�?*/
#define DPC_CANCEL_FLAG_DRY_RUN 0x2u      /* 只分类未摘除 */
#define DPC_CANCEL_FLAG_SCAN_PARTIAL 0x4u /* 部分 CPU/队列未能扫描 */
#define DPC_CANCEL_FLAG_SINGLY_LINKED 0x8u /* 观察�?24H2+ 单链表队�?*/
#define DPC_CANCEL_FLAG_DEQUEUE_UNSUPPORTED 0x10u /* 布局不支持摘�?*/
#define DPC_CANCEL_FLAG_LIMIT_REACHED 0x20u /* 达到 MaxCancel 上限 */

/* 嫌疑判定依据的位组合 */
#define DPC_CANCEL_REASON_NONCANONICAL_CONTEXT 0x1u /* Context 非规�?*/
#define DPC_CANCEL_REASON_ROUTINE_IN_NTOS 0x2u      /* Routine �?ntoskrnl �?*/
#define DPC_CANCEL_REASON_NULL_CONTEXT 0x4u         /* Context �?NULL（合法，不作为嫌疑） */
#define DPC_CANCEL_REASON_ROUTINE_OUTSIDE 0x8u      /* Routine 不在 ntoskrnl �?*/
#define DPC_CANCEL_REASON_ROUTINE_INVALID 0x10u     /* Routine 不是内核地址 */
#define DPC_CANCEL_REASON_CANCELLED 0x20u           /* 已成功摘�?*/
#define DPC_CANCEL_REASON_DEQUEUE_FAILED 0x40u      /* 判定为嫌疑但摘除失败 */

typedef struct _DPC_CANCEL_ENTRY {
  ULONG Cpu;          /* 所属队列的 CPU */
  ULONG Flags;        /* DPC_CANCEL_REASON_* 位组�?*/
  ULONG_PTR DpcObject;
  ULONG_PTR Routine;
  ULONG_PTR Context;
  ULONG_PTR QueueHead; /* 所在队列头地址 */
  ULONG Confidence;
  ULONG Evidence;
} DPC_CANCEL_ENTRY, *PDPC_CANCEL_ENTRY;

static_assert(sizeof(DPC_CANCEL_ENTRY) == 48, "DPC_CANCEL_ENTRY ABI mismatch");

typedef struct _DPC_CANCEL_INPUT {
  ULONG DryRun;    /* �?0：只枚举分类，不实际摘除 */
  ULONG MaxCancel; /* 最多摘除多少个�? 视为 DPC_CANCEL_MAX_ENTRIES */
} DPC_CANCEL_INPUT, *PDPC_CANCEL_INPUT;

typedef struct _DPC_CANCEL_OUTPUT {
  ULONG Scanned;      /* 成功解码并检查的 DPC �?*/
  ULONG Suspects;     /* 同时满足两个条件�?DPC �?*/
  ULONG Cancelled;    /* 实际摘除�?*/
  ULONG NonCanonical; /* Context 为非规范指针的数�?*/
  ULONG RoutineInNtos;/* Routine 落在 ntoskrnl 内的数量 */
  ULONG CpuCount;     /* 参与扫描�?CPU �?*/
  ULONG TimerSource;  /* 1 = 走�?TimerTable�? = 退�?PRCB 窗口扫描 */
  ULONG Flags;        /* DPC_CANCEL_FLAG_* 位组�?*/
  ULONG NtoskrnlBaseLow; /* 诊断：ntoskrnl 基址（低 32 位） */
  ULONG NtoskrnlSize;
  ULONG EntryCount;
  ULONG _Pad0;
  DPC_CANCEL_ENTRY Entries[DPC_CANCEL_MAX_ENTRIES];
  ULONG Status;
  ULONG HighConfidenceCount;
  ULONG LowConfidenceCount;
} DPC_CANCEL_OUTPUT, *PDPC_CANCEL_OUTPUT;

/* 只读 PG routine 候选枚举：PPN 使用，不执行 DPC 摘除。 */
#define DPC_PG_CANDIDATE_MAX_ENTRIES 64

typedef struct _DPC_PG_CANDIDATE_ENTRY {
  ULONG Cpu;
  ULONG Flags;
  ULONG_PTR DpcObject;
  ULONG_PTR Routine;
  ULONG_PTR Context;
  ULONG_PTR QueueHead;
  ULONG Confidence;
  ULONG QueueSource;
  ULONG PageExecutable;
  ULONG ContextMatch;
} DPC_PG_CANDIDATE_ENTRY, *PDPC_PG_CANDIDATE_ENTRY;

static_assert(sizeof(DPC_PG_CANDIDATE_ENTRY) == 56,
              "DPC_PG_CANDIDATE_ENTRY ABI mismatch");

typedef struct _DPC_PG_CANDIDATE_OUTPUT {
  ULONG Scanned;
  ULONG RoutineInNtos;
  ULONG CandidateCount;
  ULONG CpuCount;
  ULONG Flags;
  ULONG NtoskrnlBaseLow;
  ULONG NtoskrnlSize;
  ULONG _Pad0;
  DPC_PG_CANDIDATE_ENTRY Entries[DPC_PG_CANDIDATE_MAX_ENTRIES];
  ULONG Status;
} DPC_PG_CANDIDATE_OUTPUT, *PDPC_PG_CANDIDATE_OUTPUT;

static_assert(sizeof(DPC_PG_CANDIDATE_OUTPUT) == 3624,
              "DPC_PG_CANDIDATE_OUTPUT ABI mismatch");

/* ============================================================
   PatchGuard APC 取消
   ============================================================
   遍历所有内核线程的 KernelMode APC 队列，筛�?
   KernelRoutine == ntoskrnl!KiDispatchCallout �?RundownRoutine == NULL
   的条目（PG 跨核投递的校验 APC）后从队列摘除�?*/

#define APC_CANCEL_MAX_ENTRIES 128

#define APC_CANCEL_FLAG_TRUNCATED 0x1u           /* 样本数组已截�?*/
#define APC_CANCEL_FLAG_DRY_RUN 0x2u             /* 只分类未摘除 */
#define APC_CANCEL_FLAG_SCAN_PARTIAL 0x4u        /* 部分线程/队列未能扫描 */
#define APC_CANCEL_FLAG_DEQUEUE_UNSUPPORTED 0x8u /* 布局不支持摘�?*/
#define APC_CANCEL_FLAG_LIMIT_REACHED 0x10u      /* 达到 MaxCancel 上限 */
#define APC_CANCEL_FLAG_ROUTINE_UNRESOLVED 0x20u /* KiDispatchCallout 未解�?*/

#define APC_CANCEL_REASON_KERNELROUTINE_MATCH 0x1u /* KernelRoutine == KiDispatchCallout */
#define APC_CANCEL_REASON_RUNDOWN_NULL 0x2u        /* RundownRoutine == NULL */
#define APC_CANCEL_REASON_ROUTINE_INVALID 0x4u     /* KernelRoutine 不是内核地址 */
#define APC_CANCEL_REASON_ROUTINE_IN_NTOS 0x8u     /* KernelRoutine 在 ntoskrnl 内 */
#define APC_CANCEL_REASON_CANCELLED 0x10u          /* 已成功摘链 */
#define APC_CANCEL_REASON_DEQUEUE_FAILED 0x20u     /* 判定为嫌疑但摘除失败 */
#define APC_CANCEL_REASON_NORMAL_APC 0x40u         /* 普通内核 APC（清单条目，非嫌疑） */
#define APC_CANCEL_REASON_TEST_APC 0x80u           /* 本驱动注入的标记 APC */
#define APC_CANCEL_REASON_CAPTURED 0x100u          /* 来自投递捕获（hook）的记录 */
#define APC_CANCEL_REASON_BLOCKED 0x200u           /* 被阻断的 PG APC 投递 */

typedef struct _APC_CANCEL_ENTRY {
  ULONG ThreadId;      /* 所属线�?TID */
  ULONG Cpu;           /* 保留：所属队�?CPU（当前恒 0�?*/
  ULONG Flags;         /* APC_CANCEL_REASON_* 位组�?*/
  ULONG _Pad0;
  ULONG_PTR ApcObject; /* _KAPC 地址 */
  ULONG_PTR KernelRoutine;
  ULONG_PTR RundownRoutine;
  ULONG_PTR Context;   /* _KAPC 携带的上下文 */
  ULONG_PTR QueueHead; /* 所�?APC 队列头地址 */
  ULONG Confidence;
  ULONG Evidence;
} APC_CANCEL_ENTRY, *PAPC_CANCEL_ENTRY;

static_assert(sizeof(APC_CANCEL_ENTRY) == 64, "APC_CANCEL_ENTRY ABI mismatch");

typedef struct _APC_CANCEL_INPUT {
  ULONG DryRun;    /* 非 0：只枚举分类，不实际摘除 */
  ULONG MaxCancel; /* 最多摘除多少个；0 视为 APC_CANCEL_MAX_ENTRIES */
  ULONG_PTR TargetApcObject; /* non-zero: target a single APC */
  ULONG     TargetThreadId;  /* optional thread filter */
  ULONG     _Pad1;
} APC_CANCEL_INPUT, *PAPC_CANCEL_INPUT;
static_assert(sizeof(APC_CANCEL_INPUT) == 24, "APC_CANCEL_INPUT ABI mismatch");

typedef struct _APC_CANCEL_OUTPUT {
  ULONG Scanned;       /* 成功解码并检查的 APC �?*/
  ULONG Suspects;      /* 同时满足两个条件�?APC �?*/
  ULONG Cancelled;     /* 实际摘除�?*/
  ULONG Matched;       /* KernelRoutine == KiDispatchCallout 的数�?*/
  ULONG RundownNull;   /* RundownRoutine == NULL 的数�?*/
  ULONG ThreadCount;   /* 参与扫描的线程数 */
  ULONG Resolved;      /* 1 = KiDispatchCallout 已解�?*/
  ULONG Flags;         /* APC_CANCEL_FLAG_* 位组�?*/
  ULONG NtoskrnlBaseLow; /* 诊断：ntoskrnl 基址（低 32 位） */
  ULONG NtoskrnlSize;
  ULONG EntryCount;
  ULONG ApcListHeadOffset; /* 诊断：_KTHREAD.ApcListHead[KernelMode] 偏移 */
  APC_CANCEL_ENTRY Entries[APC_CANCEL_MAX_ENTRIES];
  ULONG Status;
  ULONG ResolverConfidence;
  ULONG ResolverAnchorCount;
  ULONG HighConfidenceCount;
  ULONG LowConfidenceCount;
} APC_CANCEL_OUTPUT, *PAPC_CANCEL_OUTPUT;

/* 调试状态查询输出：仅包含钩子安装状态与 IsDebuggerEnabled 内核变量�?*/
typedef struct _DEBUG_STATE_OUTPUT {
  BOOLEAN HookInstalled;      /* KdSystemDebugControl 跳板是否已安装（1=拦截调试请求�?*/
  BOOLEAN IsDebuggerEnabled;  /* ntoskrnl KdDebuggerEnabled 导出变量的当前值（1=已连接调试器�?*/
  UCHAR _Pad[6];
  ULONG Status;               /* 0 = 查询成功；非 0 �?NTSTATUS */
} DEBUG_STATE_OUTPUT, *PDEBUG_STATE_OUTPUT;

typedef struct _SYSTEM_TABLES_OUTPUT {
  ULONG_PTR IdtBase;
  USHORT IdtLimit;
  USHORT _Pad1;

  ULONG_PTR GdtBase;
  USHORT GdtLimit;
  USHORT _Pad2;

  ULONG_PTR KuserSharedData;
  ULONG64 InterruptTime;
  ULONG64 SystemTime;
  ULONG TickCount;
  ULONG _Pad3;

  ULONG_PTR SsdtBase;
  ULONG SsdtCount;
  ULONG_PTR SsdtArgTable;

  ULONG_PTR ShadowSsdtBase;
  ULONG ShadowSsdtCount;
  ULONG_PTR ShadowSsdtArgTable;

  ULONG_PTR PiDDBCacheTable;

  ULONG_PTR NtoskrnlBase;
  ULONG NtoskrnlSize;
  ULONG _Pad4;
  ULONG64 Cr0;
  ULONG64 Cr2;
  ULONG64 Cr3;
  ULONG64 Cr4;
  ULONG64 MsrLstar;
  ULONG64 MsrStar;
  ULONG64 MsrFmask;
  ULONG64 MsrEfer;

  /* ---- 诊断（与驱动 SystemTable.h 同步追加�?---- */
  ULONG     PiDdbLeaScore;
  ULONG     PiDdbSigScore;
  ULONG     PiDdbLeaCandidates;
  ULONG     PiDdbSigCandidates;
  ULONG_PTR PiDdbSigBest;
  /* 链式表发现诊断；实际布局通过结构校验判定，不绑定系统版本�?*/
  ULONG     PiDdbListScore;
  ULONG     PiDdbListCandidates;
} SYSTEM_TABLES_OUTPUT, *PSYSTEM_TABLES_OUTPUT;

#define SYSTEM_TABLE_KIND_IDT 0
#define SYSTEM_TABLE_KIND_IO_TIMER 1
#define SYSTEM_TABLE_KIND_SSDT 2
#define SYSTEM_TABLE_KIND_SHADOW_SSDT 3
#define SYSTEM_TABLE_KIND_GDT 4
#define SYSTEM_TABLE_MAX_ENTRIES 4096
#define PIDDB_CACHE_MAX_ENTRIES 1024
#define HAL_DISPATCH_TABLE_ENTRIES 16
#define HAL_DISPATCH_TABLE_KIND_PUBLIC 5
#define HAL_DISPATCH_TABLE_KIND_PRIVATE 6
#define DPC_MAX_ENTRIES 256
#define THREAD_ENUM_BATCH_SIZE 512
#define THREAD_ENUM_VERSION 1

typedef struct _AEGIS_SYSTEM_TABLE_ENTRY {
  ULONG Index;
  ULONG ArgumentBytes;
  ULONG_PTR Address;
} SYSTEM_TABLE_ENTRY, *PSYSTEM_TABLE_ENTRY;

typedef struct _AEGIS_SYSTEM_TABLE_ENTRIES_OUTPUT {
  ULONG TableKind;
  ULONG Count;
  ULONG TotalCount;
  ULONG_PTR TableBase;
  SYSTEM_TABLE_ENTRY Entries[SYSTEM_TABLE_MAX_ENTRIES];
} SYSTEM_TABLE_ENTRIES_OUTPUT, *PSYSTEM_TABLE_ENTRIES_OUTPUT;

typedef struct _THREAD_ENUM_INPUT {
  ULONG Size;
  ULONG Version;
  ULONG Cursor;
  ULONG Reserved;
} THREAD_ENUM_INPUT, *PTHREAD_ENUM_INPUT;

#define THREAD_FIELD_OK         0u
#define THREAD_FIELD_LOOKUP     1u
#define THREAD_FIELD_FAULT      2u
#define THREAD_FIELD_NOT_APPLIC 3u

typedef struct _THREAD_ENUM_ENTRY {
  ULONG Index;
  ULONG ThreadId;
  ULONG ProcessId;
  ULONG PreviousMode;
  ULONG_PTR Ethread;
  ULONG_PTR StartAddress;
  ULONG_PTR UserTime;
  ULONG_PTR KernelTime;
  UCHAR ApcQueueable;
  UCHAR PrevModeStatus;
  UCHAR ApcStatus;
  UCHAR _Pad[5];
  ULONG Priority;
  ULONG State;
} THREAD_ENUM_ENTRY, *PTHREAD_ENUM_ENTRY;

static_assert(sizeof(THREAD_ENUM_ENTRY) == 64, "THREAD_ENUM_ENTRY ABI mismatch");

typedef struct _THREAD_ENUM_OUTPUT {
  ULONG Size;
  ULONG Version;
  ULONG Count;
  ULONG TotalCount;
  ULONG NextCursor;
  ULONG Reserved;
  THREAD_ENUM_ENTRY Entries[THREAD_ENUM_BATCH_SIZE];
} THREAD_ENUM_OUTPUT, *PTHREAD_ENUM_OUTPUT;

typedef struct _THREAD_ID_INPUT {
  ULONG ThreadId;
} THREAD_ID_INPUT, *PTHREAD_ID_INPUT;

typedef struct _THREAD_PREVIOUS_MODE_INPUT {
  ULONG ThreadId;
  UCHAR PreviousMode;
  UCHAR _Pad[3];
} THREAD_PREVIOUS_MODE_INPUT, *PTHREAD_PREVIOUS_MODE_INPUT;

typedef struct _THREAD_APC_QUEUEABLE_INPUT {
  ULONG ThreadId;
  UCHAR Value;
  UCHAR _Pad[3];
} THREAD_APC_QUEUEABLE_INPUT, *PTHREAD_APC_QUEUEABLE_INPUT;

#define DPC_SOURCE_NONE 0u
#define DPC_SOURCE_TIMER_TABLE 1u
#define DPC_SOURCE_WINDOW_SCAN 2u
#define DPC_SNAPSHOT_TRUNCATED 0x1u
#define DPC_SNAPSHOT_SCAN_INCOMPLETE 0x2u
#define DPC_SNAPSHOT_DIAGNOSTICS_VALID 0x80000000u
#define DPC_ENTRY_FLAG_IN_QUEUE       0x00000001u
#define DPC_ENTRY_FLAG_TIMER_REFERENCE 0x00000002u
#define DPC_ENTRY_FLAG_THREADED       0x00000004u

typedef struct _DPC_ENUM_ENTRY {
  ULONG Index;
  ULONG Cpu; /* Owning timer table / queue CPU, not the execution target. */
  ULONG_PTR DpcObject;
  ULONG_PTR Routine;
  ULONG_PTR Context;
  ULONG_PTR DueTime; /* raw KTIMER.DueTime (not encoded); 0 when unavailable */
  ULONG Encoded;     /* 1 = DpcObject decoded from KTIMER.Dpc */
  ULONG Flags;
} DPC_ENUM_ENTRY, *PDPC_ENUM_ENTRY;

static_assert(sizeof(DPC_ENUM_ENTRY) == 48, "DPC_ENUM_ENTRY ABI mismatch");

typedef struct _DPC_ENUM_OUTPUT {
  ULONG Count;
  ULONG TotalCount; /* Valid references observed before deduplication/sampling. */
  ULONG CpuCount;
  DPC_ENUM_ENTRY Entries[DPC_MAX_ENTRIES];

  /* ---- 诊断（与驱动 SystemTable.h 同步追加�?---- */
  ULONG DpcScanWindow;
  ULONG DpcPrcbCount;
  ULONG DpcCandidateCount;
  ULONG DpcAcceptedCount;

  /* ---- TimerTable 路径诊断 ---- */
  ULONG DpcSource;         /* DPC_SOURCE_* */
  ULONG TimerTableOffset;  /* KPRCB 内偏移，0 表示未定�?*/
  ULONG TimerTableBuckets; /* 实际走到的桶�?*/
  ULONG TimerTableEntryOffset; /* 桶头�?KTIMER_TABLE_ENTRY 内的偏移 */
  ULONG TimerDecodedCount;
  ULONG TimerDecodeFailCount;
  ULONG PrcbResolveSource; /* 1=导出数组�?=经当�?CPU 校验的访问器引用 */
  ULONG KeyResolveSource;  /* 1=从已验证的编码指令提取，0=未取�?*/
  union { ULONG SnapshotFlags; ULONG _PadKeys; }; /* Reserved slot; ABI unchanged. */
  ULONG_PTR KiWaitNeverAddress;
  ULONG_PTR KiWaitAlwaysAddress;
  ULONG64 KiWaitNeverValue;
  ULONG64 KiWaitAlwaysValue;
} DPC_ENUM_OUTPUT, *PDPC_ENUM_OUTPUT;

typedef struct _DPC_REMOVE_INPUT {
  ULONG_PTR DpcObject;
  ULONG Cpu;
} DPC_REMOVE_INPUT, *PDPC_REMOVE_INPUT;

typedef struct _PIDDB_REMOVE_INPUT {
  ULONG_PTR EntryAddress;
} PIDDB_REMOVE_INPUT, *PPIDDB_REMOVE_INPUT;

typedef struct _PIDDB_CACHE_ENTRY_INFO {
  ULONG Index;
  ULONG TimeDateStamp;
  LONG LoadStatus;
  ULONG_PTR Address;
  WCHAR DriverName[128];
} PIDDB_CACHE_ENTRY_INFO, *PPIDDB_CACHE_ENTRY_INFO;

typedef struct _PIDDB_CACHE_ENUM_OUTPUT {
  ULONG Count;
  ULONG TotalCount;
  ULONG_PTR TableAddress;
  PIDDB_CACHE_ENTRY_INFO Entries[PIDDB_CACHE_MAX_ENTRIES];

  /* ---- 诊断（发现路径得分，与驱�?SystemTable.h 同步追加�?---- */
  ULONG LeaScore;
  ULONG ListScore;
  ULONG SigScore;
  ULONG LeaCandidates;
  ULONG ListCandidates;
  ULONG SigCandidates;
  ULONG_PTR SigBest;
} PIDDB_CACHE_ENUM_OUTPUT, *PPIDDB_CACHE_ENUM_OUTPUT;

/* ---- 全局热键枚举（IOCTL 0x86D，与驱动 SystemTable.h 同步�?---- */
#define HOTKEY_MAX_ENTRIES 256
#define IOCTL_REMOVE_HOTKEY CTL_CODE(0x8000, 0x88B, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOTKEY_ENUM_ENTRY {
  ULONG Index;
  ULONG ProcessId;
  LONG Id;
  ULONG VirtualKey;
  ULONG Modifiers;
  ULONG Flags;
  ULONG_PTR HotKeyObject;
  ULONG_PTR WindowObject;
  ULONG_PTR ThreadInfo;
} HOTKEY_ENUM_ENTRY, *PHOTKEY_ENUM_ENTRY;

typedef struct _HOTKEY_REMOVE_INPUT {
  ULONG Size;
  ULONG Version;
  HOTKEY_ENUM_ENTRY Entry;
} HOTKEY_REMOVE_INPUT, *PHOTKEY_REMOVE_INPUT;

typedef struct _HOTKEY_REMOVE_DIAGNOSTIC {
    ULONG64 Actual;
    ULONG64 Resolved;
    ULONG64 Expected;
    ULONG64 Alternate;
    ULONG64 BaseImage;
    ULONG64 FullImage;
    UCHAR Code[16];
    ULONG CodeSize;
    ULONG Reserved;
} HOTKEY_REMOVE_DIAGNOSTIC;

typedef struct _HOTKEY_REMOVE_OUTPUT {
    ULONG Size;
    NTSTATUS KernelStatus;
    ULONG Detail;
    ULONG Reserved;
    HOTKEY_REMOVE_DIAGNOSTIC Diagnostic;
} HOTKEY_REMOVE_OUTPUT, *PHOTKEY_REMOVE_OUTPUT;

#define HOTKEY_REMOVE_DETAIL_NONE             0u
#define HOTKEY_REMOVE_DETAIL_IMAGE            1u
#define HOTKEY_REMOVE_DETAIL_EXPORT           2u
#define HOTKEY_REMOVE_DETAIL_ENTRY_PATTERN    3u
#define HOTKEY_REMOVE_DETAIL_LEAVE_EXPORT     4u
#define HOTKEY_REMOVE_DETAIL_ENTRY_IMPORT     5u
#define HOTKEY_REMOVE_DETAIL_THREAD_IMPORT    6u
#define HOTKEY_REMOVE_DETAIL_WRAPPER          7u
#define HOTKEY_REMOVE_DETAIL_CORE             8u
#define HOTKEY_REMOVE_DETAIL_DELETE           9u
#define HOTKEY_REMOVE_DETAIL_TABLE           10u
#define HOTKEY_REMOVE_DETAIL_SESSION_IMAGE   11u
#define HOTKEY_REMOVE_DETAIL_SESSION_IMPORT  12u
#define HOTKEY_REMOVE_DETAIL_SESSION_OFFSET  13u
#define HOTKEY_REMOVE_DETAIL_SESSION_POINTER 14u
#define HOTKEY_REMOVE_DETAIL_SESSION_TABLE   15u
#define HOTKEY_REMOVE_DETAIL_SPECIAL_WINDOW  16u
#define HOTKEY_REMOVE_DETAIL_INTERNAL_ENTRY  17u
#define HOTKEY_REMOVE_DETAIL_LINKED_ENTRY    18u
#define HOTKEY_REMOVE_DETAIL_GUI_CONTEXT     19u
#define HOTKEY_REMOVE_DETAIL_STALE_ENTRY     20u
#define HOTKEY_REMOVE_DETAIL_DELETE_FAILED   21u
#define HOTKEY_REMOVE_DETAIL_ENTER_TARGET    22u
#define HOTKEY_REMOVE_DETAIL_LEAVE_TARGET    23u
#define HOTKEY_REMOVE_DETAIL_ENTER_SLOT      24u
#define HOTKEY_REMOVE_DETAIL_LEAVE_SLOT      25u

static_assert(sizeof(HOTKEY_REMOVE_INPUT) == 56, "HOTKEY_REMOVE_INPUT ABI mismatch");
static_assert(sizeof(HOTKEY_REMOVE_OUTPUT) == 88, "HOTKEY_REMOVE_OUTPUT ABI mismatch");

static_assert(sizeof(HOTKEY_ENUM_ENTRY) == 48, "HOTKEY_ENUM_ENTRY ABI mismatch");

typedef struct _HOTKEY_ENUM_OUTPUT {
  ULONG Count;
  ULONG TotalCount;
  ULONG_PTR TableAddress;
  HOTKEY_ENUM_ENTRY Entries[HOTKEY_MAX_ENTRIES];

  /* ---- 诊断（与驱动 SystemTable.h 同步追加�?---- */
  ULONG_PTR Win32kBase;
  ULONG CandidateCount;
  ULONG AcceptedCount;
} HOTKEY_ENUM_OUTPUT, *PHOTKEY_ENUM_OUTPUT;

typedef struct _IDT_LIMIT_INPUT {
  USHORT NewEntryCount;
} IDT_LIMIT_INPUT, *PIDT_LIMIT_INPUT;

typedef struct _IDT_LIMIT_OUTPUT {
  ULONG_PTR OldBase;
  USHORT OldLimit;
  USHORT OldEntryCount;
  ULONG_PTR NewBase;
  USHORT NewLimit;
  USHORT NewEntryCount;
  USHORT EntrySize;
  BOOLEAN Changed;
} IDT_LIMIT_OUTPUT, *PIDT_LIMIT_OUTPUT;

typedef struct _DRIVER_ENUM_ENTRY {
  WCHAR ServiceName[128];
  WCHAR DisplayName[128];
  WCHAR ImagePath[260];
  WCHAR RegistryPath[260];
  ULONG State;
  ULONG Type;
  ULONG StartType;
  ULONG ErrorControl;
  ULONG_PTR DriverObject;
  ULONG_PTR ImageBase;
  ULONG ImageSize;
  ULONG Reserved;
} DRIVER_ENUM_ENTRY, *PDRIVER_ENUM_ENTRY;

typedef struct _DRIVER_ENUM_HEADER {
  LONG NtStatus;
  ULONG Count;
  WCHAR Message[256];
} DRIVER_ENUM_HEADER, *PDRIVER_ENUM_HEADER;

typedef struct _DRIVER_ENUM_OUTPUT {
  DRIVER_ENUM_HEADER Header;
  DRIVER_ENUM_ENTRY Entries[1];
} DRIVER_ENUM_OUTPUT, *PDRIVER_ENUM_OUTPUT;

typedef struct _DRIVER_CONTROL_INPUT {
  WCHAR ServiceName[128];
  WCHAR ImagePath[260];
  BOOLEAN DeleteOnUnload;
  UCHAR Reserved[3];
} DRIVER_CONTROL_INPUT, *PDRIVER_CONTROL_INPUT;

typedef struct _DRIVER_CONTROL_OUTPUT {
  LONG NtStatus;
  ULONG State;
  ULONG Type;
  ULONG StartType;
  ULONG ErrorControl;
  ULONG_PTR DriverObject;
  ULONG_PTR ImageBase;
  ULONG ImageSize;
  WCHAR RegistryPath[260];
  WCHAR ImagePath[260];
  WCHAR Message[512];
} DRIVER_CONTROL_OUTPUT, *PDRIVER_CONTROL_OUTPUT;

typedef struct _DRIVER_HIDE_INPUT {
  WCHAR ServiceName[128];
  ULONG Reserved;
} DRIVER_HIDE_INPUT, *PDRIVER_HIDE_INPUT;

typedef struct _DRIVER_HIDE_OUTPUT {
  LONG NtStatus;
  ULONG Reserved;
  WCHAR Message[256];
} DRIVER_HIDE_OUTPUT, *PDRIVER_HIDE_OUTPUT;

#define INVENTORY_PROTOCOL_VERSION 2u
#define INVENTORY_MAX_PAGE_RECORDS 256u

enum INVENTORY_DATA_SOURCE : ULONG {
  InventorySourceUnknown = 0,
  InventorySourcePublicApi,
  InventorySourceSystemInformation,
  InventorySourceObjectManager,
  InventorySourceRegistry,
  InventorySourceProcessEnvironment,
  InventorySourceMemoryMap,
  InventorySourceVersionProfile,
  InventorySourceSignatureScan,
  InventorySourceCrossView,
  InventorySourceKernelStructure
};
enum INVENTORY_CONFIDENCE : ULONG {
  InventoryConfidenceUnavailable = 0,
  InventoryConfidenceLow,
  InventoryConfidenceMedium,
  InventoryConfidenceHigh
};
typedef struct _INVENTORY_QUERY_INPUT {
  ULONG Size;
  ULONG Version;
  ULONG Flags;
  ULONG ProcessId;
  ULONG TargetId;
  ULONG MaxEntries;
  ULONG64 Cursor;
  WCHAR Name[128];
  WCHAR Path[260];
} INVENTORY_QUERY_INPUT, *PINVENTORY_QUERY_INPUT;
typedef struct _INVENTORY_LIST_HEADER {
  ULONG Size;
  ULONG Version;
  LONG Status;
  ULONG Source;
  ULONG Confidence;
  ULONG Flags;
  ULONG TotalCount;
  ULONG ReturnedCount;
  ULONG RequiredSize;
  ULONG Reserved;
  ULONG64 NextCursor;
} INVENTORY_LIST_HEADER, *PINVENTORY_LIST_HEADER;
typedef struct _INVENTORY_RECORD {
  ULONG Size;
  ULONG Kind;
  ULONG Flags;
  ULONG Source;
  ULONG Confidence;
  LONG Status;
  ULONG ProcessId;
  ULONG ThreadId;
  ULONG64 Address;
  ULONG64 SizeBytes;
  ULONG64 Value[8];
  WCHAR Name[128];
  WCHAR TypeName[64];
  WCHAR Path[260];
  WCHAR Detail[256];
} INVENTORY_RECORD, *PINVENTORY_RECORD;
typedef struct _INVENTORY_CAPABILITIES_OUTPUT {
  INVENTORY_LIST_HEADER Header;
  ULONG OsMajor;
  ULONG OsMinor;
  ULONG OsBuild;
  ULONG Architecture;
  ULONG64 StableCapabilities;
  ULONG64 ExperimentalCapabilities;
} INVENTORY_CAPABILITIES_OUTPUT, *PINVENTORY_CAPABILITIES_OUTPUT;
typedef struct _INVENTORY_LIST_OUTPUT {
  INVENTORY_LIST_HEADER Header;
  INVENTORY_RECORD Records[1];
} INVENTORY_LIST_OUTPUT, *PINVENTORY_LIST_OUTPUT;
typedef struct _ADVANCED_OPERATION_INPUT {
  ULONG Size, Version, Kind, Operation, ProcessId, TargetId;
  ULONG64 Address, Value, TransactionId;
  WCHAR Name[128];
} ADVANCED_OPERATION_INPUT, *PADVANCED_OPERATION_INPUT;
typedef struct _ADVANCED_OPERATION_OUTPUT {
  ULONG Size, Version;
  LONG Status;
  ULONG Flags;
  ULONG64 TransactionId, BeforeValue, AfterValue;
  WCHAR Detail[128];
} ADVANCED_OPERATION_OUTPUT, *PADVANCED_OPERATION_OUTPUT;
static_assert(sizeof(ADVANCED_OPERATION_INPUT) == 304, "Advanced V3 input ABI mismatch");
static_assert(sizeof(ADVANCED_OPERATION_OUTPUT) == 296, "Advanced V3 output ABI mismatch");

/* ---- 线程劫持 / 远端调用 ---- */
typedef struct _THREAD_HIJACK_INPUT {
  ULONG ThreadId;
  ULONG_PTR TargetRip;
} THREAD_HIJACK_INPUT, *PTHREAD_HIJACK_INPUT;

typedef struct _THREAD_REMOTE_CALL_INPUT {
  ULONG ThreadId;
  ULONG_PTR Function;
  ULONG_PTR Args[4];
} THREAD_REMOTE_CALL_INPUT, *PTHREAD_REMOTE_CALL_INPUT;

typedef struct _THREAD_REMOTE_CALL_OUTPUT {
  LONG Result;
} THREAD_REMOTE_CALL_OUTPUT, *PTHREAD_REMOTE_CALL_OUTPUT;

typedef struct _SHELLCODE_INJECT_INPUT {
  ULONG Id;
  ULONG Size;
} SHELLCODE_INJECT_INPUT, *PSHELLCODE_INJECT_INPUT;

typedef struct _SHELLCODE_INJECT_OUTPUT {
  ULONG_PTR AllocatedAddress;
  LONG Status;
} SHELLCODE_INJECT_OUTPUT, *PSHELLCODE_INJECT_OUTPUT;

static_assert(sizeof(INVENTORY_QUERY_INPUT) == 808,
              "AegisCore V2 request ABI mismatch");
static_assert(sizeof(INVENTORY_LIST_HEADER) == 48,
              "AegisCore V2 header ABI mismatch");
static_assert(sizeof(INVENTORY_RECORD) == 1528, "AegisCore V2 record ABI mismatch");
static_assert(sizeof(INVENTORY_CAPABILITIES_OUTPUT) == 80,
              "AegisCore V2 capabilities ABI mismatch");

#define WINDOW_OP_CLOSE 0
#define WINDOW_OP_HIDE 1
#define WINDOW_OP_SHOW 2
#define WINDOW_OP_SET_TITLE 3
#define WINDOW_OP_MINIMIZE 4
#define WINDOW_OP_RESTORE 5
#define WINDOW_OP_SET_POSITION 6
#define WINDOW_OP_SET_SIZE 7
#define WINDOW_OP_ENABLE 8
#define WINDOW_OP_DISABLE 9
#define WINDOW_OP_SET_TOPMOST 10
#define WINDOW_OP_REMOVE_TOPMOST 11
#define WINDOW_OP_FLASH 12
#define WINDOW_OP_REDRAW 13
#define WINDOW_OP_MAXIMIZE 14
#define WINDOW_OP_PING 15

#define WINDOW_FLAG_DIRECT 0x00000001
#define WINDOW_FLAG_FORCE 0x00000002

#define WINDOW_FLAG_VISIBLE (1ul << 0)
#define WINDOW_FLAG_ENABLED (1ul << 1)
#define WINDOW_FLAG_HUNG (1ul << 2)
#define WINDOW_FLAG_MINIMIZED (1ul << 3)
#define WINDOW_FLAG_MAXIMIZED (1ul << 4)
#define WINDOW_FLAG_TOPMOST (1ul << 5)
#define WINDOW_FLAG_LAYERED (1ul << 6)
#define WINDOW_FLAG_TOOLWINDOW (1ul << 7)
#define WINDOW_FLAG_POPUP (1ul << 8)
#define WINDOW_FLAG_CHILD (1ul << 9)
#define WINDOW_FLAG_UNICODE (1ul << 10)
#define WINDOW_FLAG_MDI (1ul << 11)
#define WINDOW_FLAG_APPWINDOW (1ul << 12)
#define WINDOW_FLAG_ACTIVE (1ul << 13)
#define WINDOW_FLAG_NOACTIVATE (1ul << 14)
#define WINDOW_FLAG_DISABLED_CLOSE (1ul << 15)
#define WINDOW_FLAG_CLOAKED (1ul << 16)
#define WINDOW_FLAG_SKIPANIMATION (1ul << 17)
#define WINDOW_FLAG_SKIPTHEME (1ul << 18)
#define WINDOW_FLAG_DESTROYED (1ul << 19)

typedef struct _KERNEL_WINDOW_ENUM_ENTRY {
  UINT64 Hwnd;
  UINT64 ParentHwnd;
  UINT64 OwnerHwnd;
  UINT64 WndProc;
  ULONG ProcessId;
  ULONG ThreadId;
  UINT64 DesktopId;
  UINT64 WinstaId;
  ULONG Style;
  ULONG ExStyle;
  ULONG State;
  ULONG ShowCmd;
  LONG Left, Top, Right, Bottom;
  LONG ClientLeft, ClientTop, ClientRight, ClientBottom;
  UCHAR Alpha;
  UCHAR Padding1[3];
  USHORT ClassAtom;
  USHORT CbWndExtra;
  ULONG Flags;
  UINT64 FirstChild;
  UINT64 NextSibling;
  UINT64 MenuHandle;
  UINT64 ThreadInfoId;
  ULONG MessageCount;
  ULONG Padding2;
  USHORT TitleLength;
  USHORT ClassLength;
} KERNEL_WINDOW_ENUM_ENTRY, *PKERNEL_WINDOW_ENUM_ENTRY;

typedef struct _KERNEL_WINDOW_ENUM_OUTPUT {
  ULONG Count;
  KERNEL_WINDOW_ENUM_ENTRY Entries[1];
} KERNEL_WINDOW_ENUM_OUTPUT, *PKERNEL_WINDOW_ENUM_OUTPUT;

typedef struct _KERNEL_WINDOW_OPERATION_INPUT {
  ULONG ProcessId;
  UINT64 Hwnd;
  ULONG Operation;
  ULONG Flags;
  WCHAR NewTitle[256];
  LONG NewX;
  LONG NewY;
  LONG NewWidth;
  LONG NewHeight;
} KERNEL_WINDOW_OPERATION_INPUT, *PKERNEL_WINDOW_OPERATION_INPUT;

typedef struct _COMMAND_LINE_INPUT {
  ULONG ProcessId;
} COMMAND_LINE_INPUT, *PCOMMAND_LINE_INPUT;

typedef struct _REG_OPERATION_INPUT {
  ULONG Operation;
  WCHAR KeyPath[260];
  WCHAR ValueName[128];
  ULONG ValueType;
  ULONG ValueDataSize;
} REG_OPERATION_INPUT, *PREG_OPERATION_INPUT;

typedef struct _SERVICE_OPERATION_INPUT {
  ULONG Operation;
  WCHAR ServiceName[128];
  ULONG ServiceType;
} SERVICE_OPERATION_INPUT, *PSERVICE_OPERATION_INPUT;

typedef struct _SESSION_OPERATION_INPUT {
  ULONG SessionId;
  ULONG Operation;
} SESSION_OPERATION_INPUT, *PSESSION_OPERATION_INPUT;

typedef struct _MITIGATION_SET_INPUT {
  ULONG ProcessId;
  ULONG PolicyId;
  ULONG64 Flags;
} MITIGATION_SET_INPUT, *PMITIGATION_SET_INPUT;

typedef struct _FIREWALL_OPERATION_INPUT {
  ULONG Operation;
  WCHAR RuleName[128];
  ULONG Action;
  ULONG RemotePort;
  ULONG Protocol;
  ULONG RemoteIpv4;      /* network byte order, 0 = any */
  UCHAR RemoteIpv6[16];  /* all zero = any */
  ULONG DirectionMask;   /* bit0 = outbound, bit1 = inbound, 0 = both */
  ULONG FamilyMask;      /* bit0 = v4, bit1 = v6, 0 = both */
} FIREWALL_OPERATION_INPUT, *PFIREWALL_OPERATION_INPUT;
static_assert(sizeof(FIREWALL_OPERATION_INPUT) == 300,
              "Firewall operation input ABI mismatch");

typedef struct _FIREWALL_RULE_ENTRY {
  ULONG64 FilterId;
  ULONG Action;
  ULONG Protocol;
  ULONG RemotePort;
  ULONG Direction;
  ULONG Enabled;
  ULONG RemoteIpv4;      /* network byte order, 0 = not specified */
  UCHAR RemoteIpv6[16];
  WCHAR RuleName[128];
} FIREWALL_RULE_ENTRY;

typedef struct _FIREWALL_RULE_OUTPUT {
  ULONG Size;
  ULONG Count;
  ULONG TotalCount;
  ULONG KernelStatus; /* raw NTSTATUS from the failing WFP call, 0 on success */
  FIREWALL_RULE_ENTRY Entries[FIREWALL_RULE_MAX_ENTRIES];
} FIREWALL_RULE_OUTPUT;

static_assert(sizeof(FIREWALL_RULE_ENTRY) == 304,
              "Firewall rule entry ABI mismatch");
static_assert(sizeof(FIREWALL_RULE_OUTPUT) == 38928,
              "Firewall rule output ABI mismatch");

// ---- 内核特征码扫�?(IOCTL 0x87F) ----
#define IOCTL_KERNEL_PATTERN_SCAN                                               \
  CTL_CODE(0x8000, 0x87F, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define KERNEL_PATTERN_SCAN_MAX_PATTERN  256u
#define KERNEL_PATTERN_SCAN_MAX_HITS     64u

typedef struct _KERNEL_PATTERN_SCAN_INPUT {
  ULONG Size;
  ULONG Reserved;
  WCHAR TargetModule[128];
  WCHAR PatternText[KERNEL_PATTERN_SCAN_MAX_PATTERN];
} KERNEL_PATTERN_SCAN_INPUT;

typedef struct _KERNEL_PATTERN_SCAN_HIT {
  ULONG64 Address;
  ULONG64 ModuleBase;
  ULONG Rva;
  ULONG Reserved;
  WCHAR ModuleName[64];
} KERNEL_PATTERN_SCAN_HIT;

typedef struct _KERNEL_PATTERN_SCAN_OUTPUT {
  ULONG Size;
  ULONG HitCount;
  ULONG TotalHits;
  ULONG ScannedModules;
  KERNEL_PATTERN_SCAN_HIT Hits[KERNEL_PATTERN_SCAN_MAX_HITS];
} KERNEL_PATTERN_SCAN_OUTPUT;

static_assert(sizeof(KERNEL_PATTERN_SCAN_INPUT) == 776,
              "Kernel pattern scan input ABI mismatch");
static_assert(sizeof(KERNEL_PATTERN_SCAN_HIT) == 152,
              "Kernel pattern scan hit ABI mismatch");
static_assert(sizeof(KERNEL_PATTERN_SCAN_OUTPUT) == 9744,
              "Kernel pattern scan output ABI mismatch");

// ---- 可疑（无文件映射的可执行）内存扫�?(IOCTL 0x880) ----
#define IOCTL_SUSPICIOUS_MEMORY_SCAN                                            \
  CTL_CODE(0x8000, 0x880, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define SUSPICIOUS_MEMORY_MAX_REGIONS    256u
#define SUSPECT_FLAG_UNBACKED_EXEC       0x00000001u

typedef struct _SUSPECT_MEMORY_INPUT {
  ULONG ProcessId;
  ULONG Reserved;
} SUSPECT_MEMORY_INPUT;

typedef struct _SUSPECT_MEMORY_REGION {
  ULONG64 Base;
  ULONG64 Size;
  ULONG Protect;
  ULONG Type;
  ULONG Flags;
  ULONG Reserved;
} SUSPECT_MEMORY_REGION;

typedef struct _SUSPECT_MEMORY_OUTPUT {
  ULONG Size;
  ULONG Count;
  ULONG TotalCount;
  ULONG Reserved;
  SUSPECT_MEMORY_REGION Regions[SUSPICIOUS_MEMORY_MAX_REGIONS];
} SUSPECT_MEMORY_OUTPUT;

static_assert(sizeof(SUSPECT_MEMORY_INPUT) == 8,
              "Suspect memory input ABI mismatch");
static_assert(sizeof(SUSPECT_MEMORY_REGION) == 32,
              "Suspect memory region ABI mismatch");
static_assert(sizeof(SUSPECT_MEMORY_OUTPUT) == 8208,
              "Suspect memory output ABI mismatch");

/* ---- 内存区域控制：保�?/ 分配 / 释放 (IOCTL 0x881-0x882) ---- */
#define IOCTL_MEMORY_PROTECT                                                    \
  CTL_CODE(0x8000, 0x881, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMORY_ALLOC_FREE                                                 \
  CTL_CODE(0x8000, 0x882, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MEMREGION_OP_ALLOC 1u
#define MEMREGION_OP_FREE 2u

typedef struct _MEMORY_PROTECT_INPUT {
  ULONG ProcessId;
  ULONG NewProtect;      /* PAGE_* constant */
  ULONG_PTR Address;
  ULONG64 Size;
} MEMORY_PROTECT_INPUT, *PMEMORY_PROTECT_INPUT;
static_assert(sizeof(MEMORY_PROTECT_INPUT) == 24,
              "Memory protect input ABI mismatch");

typedef struct _MEMORY_PROTECT_OUTPUT {
  LONG Status;
  ULONG OldProtect;
} MEMORY_PROTECT_OUTPUT, *PMEMORY_PROTECT_OUTPUT;

typedef struct _MEMORY_ALLOC_INPUT {
  ULONG ProcessId;
  ULONG Operation;        /* MEMREGION_OP_ALLOC / MEMREGION_OP_FREE */
  ULONG Protect;
  ULONG AllocationType;   /* 0 = reserve|commit, 1 = reserve only */
  ULONG_PTR Address;      /* free only */
  ULONG64 Size;           /* alloc only */
} MEMORY_ALLOC_INPUT, *PMEMORY_ALLOC_INPUT;
static_assert(sizeof(MEMORY_ALLOC_INPUT) == 32,
              "Memory alloc input ABI mismatch");

typedef struct _MEMORY_ALLOC_OUTPUT {
  LONG Status;
  ULONG OldProtect;
  ULONG_PTR BaseAddress;
  ULONG64 Size;
} MEMORY_ALLOC_OUTPUT, *PMEMORY_ALLOC_OUTPUT;

typedef struct _WINDOW_PROTECT_INPUT {
  ULONG ProcessId;
  ULONG64 Hwnd;
  ULONG Flags;
} WINDOW_PROTECT_INPUT, *PWINDOW_PROTECT_INPUT;

#define WINPROT_CLOSE 0x00000001
#define WINPROT_HIDE 0x00000002
#define WINPROT_TITLE 0x00000004
#define WINPROT_DISABLE 0x00000008
#define WINPROT_MOVE 0x00000010
#define WINPROT_RESIZE 0x00000020
#define WINPROT_TOPMOST 0x00000040
#define WINPROT_ALL 0xFFFFFFFF

typedef struct _INJECTION_PROTECT_INPUT {
  ULONG ProcessId;
} INJECTION_PROTECT_INPUT, *PINJECTION_PROTECT_INPUT;

/* ---- APC 投递捕获 / 测试注入（与驱动 Protect.h 对应）---- */
#define APC_CAPTURE_MAX_ENTRIES 512
#define APC_CAPTURE_UI_LIMIT 2048
#define APC_CAPTURE_FLAG_ENABLED 0x1u
#define APC_CAPTURE_FLAG_TRUNCATED 0x2u
#define APC_CAPTURE_FLAG_HOOK_EXPORT_OK 0x4u
#define APC_CAPTURE_FLAG_HOOK_INTERNAL_OK 0x8u
#define APC_CAPTURE_FLAG_DRAIN 0x10u

typedef struct _APC_CAPTURE_ENTRY {
  ULONG TargetThreadId;
  ULONG ApcMode;
  ULONG Flags;
  ULONG _Pad0;
  ULONG_PTR ApcObject;
  ULONG_PTR KernelRoutine;
  ULONG_PTR RundownRoutine;
  ULONG_PTR NormalRoutine;
  ULONG_PTR SystemArgument1;
  ULONG_PTR SystemArgument2;
  ULONG64 TimeStamp;
  ULONG64 Sequence;
} APC_CAPTURE_ENTRY, *PAPC_CAPTURE_ENTRY;
static_assert(sizeof(APC_CAPTURE_ENTRY) == 80, "APC_CAPTURE_ENTRY ABI mismatch");

typedef struct _APC_CAPTURE_CTL_INPUT {
  ULONG Enable;
  ULONG Clear;
} APC_CAPTURE_CTL_INPUT, *PAPC_CAPTURE_CTL_INPUT;

typedef struct _APC_CAPTURE_READ_INPUT {
  ULONG Drain;
  ULONG _Pad0;
} APC_CAPTURE_READ_INPUT, *PAPC_CAPTURE_READ_INPUT;

typedef struct _APC_CAPTURE_CTL_OUTPUT {
  ULONG Enabled;
  ULONG Flags;
  ULONG Captured;
  ULONG Dropped;
  ULONG Pending;
  ULONG Capacity;
  ULONG HookExportOk;
  ULONG HookInternalOk;
  ULONG Blocked;
  ULONG BlockPgEnabled;
} APC_CAPTURE_CTL_OUTPUT, *PAPC_CAPTURE_CTL_OUTPUT;

typedef struct _APC_CAPTURE_OUTPUT {
  ULONG Enabled;
  ULONG Flags;
  ULONG Captured;
  ULONG Dropped;
  ULONG Capacity;
  ULONG EntryCount;
  ULONG Blocked;
  ULONG BlockPgEnabled;
  APC_CAPTURE_ENTRY Entries[1];
} APC_CAPTURE_OUTPUT, *PAPC_CAPTURE_OUTPUT;

typedef struct _APC_TEST_INPUT {
  ULONG TargetThreadId;
  ULONG Count;
  ULONG StallMicros;
  ULONG _Pad0;
} APC_TEST_INPUT, *PAPC_TEST_INPUT;

typedef struct _APC_TEST_OUTPUT {
  ULONG Requested;
  ULONG Injected;
  ULONG TargetThreadId;
  ULONG _Pad0;
  ULONG64 TargetApcObjects[8];
} APC_TEST_OUTPUT, *PAPC_TEST_OUTPUT;

typedef struct _HANDLE_CLOSE_INPUT {
  ULONG ProcessId;
  ULONG HandleValue;
} HANDLE_CLOSE_INPUT, *PHANDLE_CLOSE_INPUT;

typedef struct _HANDLE_DOWNGRADE_INPUT {
  ULONG ProcessId;
  ULONG HandleValue;
  ACCESS_MASK NewAccess;
  ULONG NewHandleValue;
} HANDLE_DOWNGRADE_INPUT, *PHANDLE_DOWNGRADE_INPUT;

typedef struct _HANDLE_DUP_DOWNGRADE_INPUT {
  ULONG SourceProcessId;
  ULONG SourceHandle;
  ULONG TargetProcessId;
  ACCESS_MASK NewAccess;
} HANDLE_DUP_DOWNGRADE_INPUT, *PHANDLE_DUP_DOWNGRADE_INPUT;

typedef struct _HANDLE_DUP_DOWNGRADE_OUTPUT {
  ULONG_PTR NewHandle;
  ULONG Status;
} HANDLE_DUP_DOWNGRADE_OUTPUT, *PHANDLE_DUP_DOWNGRADE_OUTPUT;

inline HANDLE G_DeviceHandle = INVALID_HANDLE_VALUE;
inline DWORD G_LastAegisCoreError = ERROR_SUCCESS;
inline std::wstring G_LastAegisCoreDetails;
inline DWORD AegisCoreNtStatusToWin32(NTSTATUS Status);

inline BOOLEAN EnsureTrustedInstallerRunning(PULONG OutPid = NULL) {
  if (OutPid)
    *OutPid = 0;

  SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!Scm) {
    G_LastAegisCoreError = GetLastError();
    return FALSE;
  }

  SC_HANDLE Service = OpenServiceW(Scm, L"TrustedInstaller",
                                   SERVICE_QUERY_STATUS | SERVICE_START);
  if (!Service) {
    G_LastAegisCoreError = GetLastError();
    CloseServiceHandle(Scm);
    return FALSE;
  }

  SERVICE_STATUS_PROCESS Status{};
  DWORD BytesNeeded = 0;
  if (!QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&Status), sizeof(Status),
                            &BytesNeeded)) {
    G_LastAegisCoreError = GetLastError();
    CloseServiceHandle(Service);
    CloseServiceHandle(Scm);
    return FALSE;
  }

  if (Status.dwCurrentState != SERVICE_RUNNING) {
    if (!StartServiceW(Service, 0, NULL) &&
        GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
      G_LastAegisCoreError = GetLastError();
      CloseServiceHandle(Service);
      CloseServiceHandle(Scm);
      return FALSE;
    }

    for (int Attempt = 0; Attempt < 50; ++Attempt) {
      Sleep(100);
      if (!QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
                                reinterpret_cast<LPBYTE>(&Status),
                                sizeof(Status), &BytesNeeded))
        break;
      if (Status.dwCurrentState == SERVICE_RUNNING && Status.dwProcessId != 0) {
        if (OutPid)
          *OutPid = Status.dwProcessId;
        CloseServiceHandle(Service);
        CloseServiceHandle(Scm);
        return TRUE;
      }
      if (Status.dwCurrentState == SERVICE_STOPPED)
        break;
    }

    G_LastAegisCoreError = ERROR_SERVICE_NOT_ACTIVE;
    CloseServiceHandle(Service);
    CloseServiceHandle(Scm);
    return FALSE;
  }

  if (OutPid)
    *OutPid = Status.dwProcessId;
  CloseServiceHandle(Service);
  CloseServiceHandle(Scm);
  return TRUE;
}

inline std::mutex G_DeviceMutex;

inline BOOLEAN TryOpenDevice() {
  G_DeviceHandle =
      CreateFileW(L"\\\\.\\AegisCore", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  return G_DeviceHandle != INVALID_HANDLE_VALUE;
}

inline BOOLEAN ShouldRetryOpenDeviceError(DWORD Error) {
  switch (Error) {
  case ERROR_GEN_FAILURE:
  case ERROR_DEVICE_NOT_CONNECTED:
  case ERROR_NOT_READY:
    return TRUE;
  default:
    return FALSE;
  }
}

// MaxAttempts=1 用于轮询路径：设备节点不存在时立即失败，避免每次 IOCTL
// 阻塞在重试循环里。需要等待设备出现的启动流程显式传更大的值�?
inline BOOLEAN OpenDeviceInternal(BOOLEAN Silent, int MaxAttempts) {
  DWORD LastError = ERROR_FILE_NOT_FOUND;
  for (int Attempt = 0; Attempt < MaxAttempts; ++Attempt) {
    if (TryOpenDevice())
      return TRUE;

    LastError = GetLastError();
    if (!ShouldRetryOpenDeviceError(LastError))
      break;
    Sleep(50);
  }

  SetLastError(LastError);
  if (!Silent) {
    wprintf(L"[!] Failed to open \\\\.\\AegisCore (error %u).\n", LastError);
    wprintf(L"    Is the driver loaded? Run: sc start Ring0Core\n");
  }
  return FALSE;
}

inline BOOLEAN OpenDevice() { return OpenDeviceInternal(FALSE, 2); }

inline BOOLEAN OpenDeviceSilent() { return OpenDeviceInternal(TRUE, 1); }

inline VOID CloseDevice() {
  if (G_DeviceHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(G_DeviceHandle);
    G_DeviceHandle = INVALID_HANDLE_VALUE;
  }
}

inline BOOLEAN SendIoctl(DWORD IoControlCode, PVOID InputBuffer, DWORD InputSize) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  std::lock_guard<std::mutex> Lock(G_DeviceMutex);
  // 轮询路径静默快速失败：驱动未加载时不重试、不刷控制台�?
  // 错误码通过 G_LastAegisCoreError 返回给调用方�?
  if (!OpenDeviceSilent()) {
    G_LastAegisCoreError = GetLastError();
    return FALSE;
  }

  DWORD BytesReturned = 0;
  BOOL Result = DeviceIoControl(G_DeviceHandle, IoControlCode, InputBuffer,
                                InputSize, NULL, 0, &BytesReturned, NULL);

  if (!Result) {
    G_LastAegisCoreError = GetLastError();
    CloseDevice();
    return FALSE;
  }

  CloseDevice();
  return TRUE;
}

inline BOOLEAN SendIoctlWithOutput(DWORD IoControlCode, PVOID InputBuffer,
                            DWORD InputSize, PVOID OutputBuffer,
                            DWORD OutputSize, PDWORD BytesReturned) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  std::lock_guard<std::mutex> Lock(G_DeviceMutex);
  if (!OpenDeviceSilent()) {
    G_LastAegisCoreError = GetLastError();
    return FALSE;
  }

  BOOL Result =
      DeviceIoControl(G_DeviceHandle, IoControlCode, InputBuffer, InputSize,
                      OutputBuffer, OutputSize, BytesReturned, NULL);

  if (!Result) {
    G_LastAegisCoreError = GetLastError();
    CloseDevice();
    return FALSE;
  }

  CloseDevice();
  return TRUE;
}

inline BOOLEAN EnumProcessEntries(std::vector<PROCESS_ENUM_ENTRY> &Entries) {
  Entries.clear();

  for (int Attempt = 0; Attempt < 2; ++Attempt) {
    DWORD BytesReturned = 0;
    DWORD ProbeCount = 0;
    if (!SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0, &ProbeCount,
                             sizeof(ProbeCount), &BytesReturned)) {
      return FALSE;
    }

    if (ProbeCount == 0) {
      return TRUE;
    }

    DWORD BufSz = sizeof(PROCESS_ENUM_OUTPUT) +
                  (ProbeCount - 1) * sizeof(PROCESS_ENUM_ENTRY);
    PROCESS_ENUM_OUTPUT *Out = (PROCESS_ENUM_OUTPUT *)malloc(BufSz);
    if (Out == NULL) {
      wprintf(L"[!] Memory allocation failed.\n");
      return FALSE;
    }
    ZeroMemory(Out, BufSz);

    if (SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0, Out, BufSz,
                            &BytesReturned) &&
        Out->Count <= ProbeCount) {
      Entries.assign(Out->Entries, Out->Entries + Out->Count);
      free(Out);
      return TRUE;
    }

    free(Out);
  }

  return FALSE;
}

inline VOID KillProcess(ULONG ProcessId) {
  wprintf(L"[*] Killing process PID=%u ...\n", ProcessId);

  KILL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_KILL_PROCESS, &Input, sizeof(Input)))
    wprintf(L"[+] Process termination request sent.\n");
}

inline VOID ProcessWriteZeroMemory(ULONG ProcessId) {
  wprintf(L"[*] Writing zero memory to process PID=%u ...\n", ProcessId);

  TERMINATE_PROCESS_MEMORY_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_TERMINATE_PROCESS_MEMORY, &Input, sizeof(Input)))
    wprintf(L"[+] Process termination request sent.\n");
}

inline VOID ProtectProcess(ULONG ProcessId) {
  wprintf(L"[*] Adding process PID=%u to protection list ...\n", ProcessId);

  PROCESS_PROTECT_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_ADD_PROCESS_PROTECT, &Input, sizeof(Input)))
    wprintf(L"[+] Process PID=%u protected.\n", ProcessId);
}

inline VOID UnprotectProcess(ULONG ProcessId) {
  wprintf(L"[*] Removing process PID=%u from protection list ...\n", ProcessId);

  PROCESS_PROTECT_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_REMOVE_PROCESS_PROTECT, &Input, sizeof(Input)))
    wprintf(L"[+] Process PID=%u unprotected.\n", ProcessId);
}

inline BOOLEAN AddProcessCreateBlock(const PROCESS_CREATE_BLOCK_ENTRY &Entry) {
  PROCESS_CREATE_BLOCK_INPUT Input = {};
  Input.Operation = PROCESS_CREATE_BLOCK_OP_ADD;
  Input.Entry = Entry;
  return SendIoctl(IOCTL_ADD_PROCESS_CREATE_BLOCK, &Input, sizeof(Input));
}

inline BOOLEAN DriverImageBlockOperation(ULONG Operation,
                                  const DRIVER_IMAGE_BLOCK_ENTRY &Entry) {
  DRIVER_IMAGE_BLOCK_INPUT Input = {};
  Input.Operation = Operation;
  Input.Entry = Entry;
  return SendIoctl(IOCTL_DRIVER_IMAGE_BLOCK_OP, &Input, sizeof(Input));
}

inline BOOLEAN EnumerateDriverImageBlocks(DRIVER_IMAGE_BLOCK_OUTPUT *Output) {
  if (!Output) return FALSE;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_DRIVER_IMAGE_BLOCK, nullptr, 0,
                             Output, sizeof(*Output), &BytesReturned);
}

inline BOOLEAN ApplyProcessDisguise(const PROCESS_DISGUISE_ENTRY &Entry) {
  PROCESS_DISGUISE_INPUT Input = {};
  Input.Entry = Entry;
  return SendIoctl(IOCTL_PROCESS_DISGUISE, &Input, sizeof(Input));
}

inline BOOLEAN RemoveProcessCreateBlock(const PROCESS_CREATE_BLOCK_ENTRY &Entry) {
  PROCESS_CREATE_BLOCK_INPUT Input = {};
  Input.Operation = PROCESS_CREATE_BLOCK_OP_REMOVE;
  Input.Entry = Entry;
  return SendIoctl(IOCTL_REMOVE_PROCESS_CREATE_BLOCK, &Input, sizeof(Input));
}

inline BOOLEAN ClearProcessCreateBlocks() {
  PROCESS_CREATE_BLOCK_INPUT Input = {};
  Input.Operation = PROCESS_CREATE_BLOCK_OP_CLEAR;
  return SendIoctl(IOCTL_REMOVE_PROCESS_CREATE_BLOCK, &Input, sizeof(Input));
}

inline BOOLEAN EnumerateProcessCreateBlocks(PROCESS_CREATE_BLOCK_OUTPUT *Output) {
  if (!Output) return FALSE;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_PROCESS_CREATE_BLOCK, nullptr, 0,
                             Output, sizeof(*Output), &BytesReturned);
}

inline BOOLEAN RootkitScan(ROOTKIT_SCAN_INPUT *Input,
                    ROOTKIT_SCAN_OUTPUT *Output) {
  if (!Input || !Output) return FALSE;
  Input->Size = sizeof(*Input);
  Input->Version = 1;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ROOTKIT_SCAN, Input, sizeof(*Input),
                             Output, sizeof(*Output), &BytesReturned);
}

inline BOOLEAN EtwProviderOperate(const ETW_PROVIDER_OPERATION &Input) {
  ETW_PROVIDER_OPERATION Op = Input;
  Op.Size = sizeof(Op);
  Op.Version = 1;
  return SendIoctl(IOCTL_ETW_PROVIDER_OPERATION, &Op, sizeof(Op));
}

inline BOOLEAN EtwProviderStart() {
  ETW_PROVIDER_OPERATION Op = {};
  Op.Operation = ETW_PROVIDER_OP_START;
  return EtwProviderOperate(Op);
}

inline BOOLEAN EtwProviderStop() {
  ETW_PROVIDER_OPERATION Op = {};
  Op.Operation = ETW_PROVIDER_OP_STOP;
  return EtwProviderOperate(Op);
}

inline BOOLEAN EtwProviderEnable(ULONG Index, UCHAR Level = 0,
                          ULONG64 Keywords = 0) {
  ETW_PROVIDER_OPERATION Op = {};
  Op.Operation = ETW_PROVIDER_OP_ENABLE;
  Op.ProviderIndex = Index;
  Op.Level = Level;
  Op.MatchAnyKeyword = Keywords;
  return EtwProviderOperate(Op);
}

inline BOOLEAN EtwProviderDisable(ULONG Index) {
  ETW_PROVIDER_OPERATION Op = {};
  Op.Operation = ETW_PROVIDER_OP_DISABLE;
  Op.ProviderIndex = Index;
  return EtwProviderOperate(Op);
}

inline BOOLEAN EtwProviderQueryStatus(ETW_PROVIDER_STATUS *Output) {
  if (!Output) return FALSE;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  const BOOL Ok = SendIoctlWithOutput(IOCTL_ETW_QUERY_PROVIDERS, nullptr, 0,
                                      Output, sizeof(*Output),
                                      &BytesReturned);
  if (!Ok || BytesReturned < sizeof(*Output) ||
      Output->Version != 1 || Output->Count > ETW_PROVIDER_MAX_COUNT) {
    return FALSE;
  }
  return TRUE;
}

inline BOOLEAN MsrQueryValues(MSR_QUERY_OUTPUT *Output) {
  if (!Output) return FALSE;
  MSR_OPERATION_INPUT Input = {};
  Input.Size = sizeof(Input);
  Input.Version = 1;
  Input.Operation = MSR_OP_QUERY;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  const BOOL Ok = SendIoctlWithOutput(IOCTL_MSR_OPERATION, &Input, sizeof(Input),
                                      Output, sizeof(*Output), &BytesReturned);
  if (!Ok || BytesReturned < sizeof(*Output) || Output->Version != 1) {
    return FALSE;
  }
  return TRUE;
}

inline BOOLEAN MsrWatchEnable() {
  MSR_OPERATION_INPUT Input = {};
  Input.Size = sizeof(Input);
  Input.Version = 1;
  Input.Operation = MSR_OP_ENABLE_WATCH;
  return SendIoctl(IOCTL_MSR_OPERATION, &Input, sizeof(Input));
}

inline BOOLEAN MsrWatchDisable() {
  MSR_OPERATION_INPUT Input = {};
  Input.Size = sizeof(Input);
  Input.Version = 1;
  Input.Operation = MSR_OP_DISABLE_WATCH;
  return SendIoctl(IOCTL_MSR_OPERATION, &Input, sizeof(Input));
}

inline VOID ProtectRegistryKey(const WCHAR *KeyPath) {
  wprintf(L"[*] Adding registry key to protection: %s\n", KeyPath);

  REGISTRY_PROTECT_INPUT Input = {0};
  wcsncpy_s(Input.KeyPath, 256, KeyPath, _TRUNCATE);

  if (SendIoctl(IOCTL_ADD_REGISTRY_PROTECT, &Input, sizeof(Input)))
    wprintf(L"[+] Registry key protected.\n");
}

inline VOID UnprotectRegistryKey(const WCHAR *KeyPath) {
  wprintf(L"[*] Removing registry key from protection: %s\n", KeyPath);

  REGISTRY_PROTECT_INPUT Input = {0};
  wcsncpy_s(Input.KeyPath, 256, KeyPath, _TRUNCATE);

  if (SendIoctl(IOCTL_REMOVE_REGISTRY_PROTECT, &Input, sizeof(Input)))
    wprintf(L"[+] Registry key unprotected.\n");
}

inline BOOLEAN ProtectFile(const WCHAR *FilePath) {
  wprintf(L"[*] Adding file to protection: %s\n", FilePath);

  FILE_PROTECT_INPUT Input = {0};
  wcsncpy_s(Input.FilePath, 260, FilePath, _TRUNCATE);

  const BOOLEAN Success =
      SendIoctl(IOCTL_ADD_FILE_PROTECT, &Input, sizeof(Input));
  if (Success)
    wprintf(L"[+] File protected.\n");
  return Success;
}

inline BOOLEAN UnprotectFile(const WCHAR *FilePath) {
  wprintf(L"[*] Removing file from protection: %s\n", FilePath);

  FILE_PROTECT_INPUT Input = {0};
  wcsncpy_s(Input.FilePath, 260, FilePath, _TRUNCATE);

  const BOOLEAN Success =
      SendIoctl(IOCTL_REMOVE_FILE_PROTECT, &Input, sizeof(Input));
  if (Success)
    wprintf(L"[+] File unprotected.\n");
  return Success;
}

inline VOID SetPpl(ULONG ProcessId, UCHAR ProtectionType, UCHAR ProtectionSigner,
            BOOLEAN Audit) {
  wprintf(L"[*] Setting PPL on PID=%u Type=%u Signer=%u Audit=%u ...\n",
          ProcessId, ProtectionType, ProtectionSigner, Audit);

  PPL_CONTROL_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.ProtectionType = ProtectionType;
  Input.ProtectionSigner = ProtectionSigner;
  Input.Audit = Audit;
  Input.RemoveProtection = FALSE;

  if (SendIoctl(IOCTL_SET_PPL, &Input, sizeof(Input)))
    wprintf(L"[+] PPL set on PID=%u.\n", ProcessId);
}

inline VOID RemovePpl(ULONG ProcessId) {
  wprintf(L"[*] Removing PPL from PID=%u ...\n", ProcessId);

  PPL_CONTROL_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.RemoveProtection = TRUE;

  if (SendIoctl(IOCTL_REMOVE_PPL, &Input, sizeof(Input)))
    wprintf(L"[+] PPL removed from PID=%u.\n", ProcessId);
}

inline VOID QueryPpl(ULONG ProcessId) {
  wprintf(L"[*] Querying PPL for PID=%u ...\n", ProcessId);

  PPL_QUERY_INPUT Input = {0};
  PPL_QUERY_OUTPUT Output = {0};
  DWORD BytesReturned = 0;
  Input.ProcessId = ProcessId;

  if (!SendIoctlWithOutput(IOCTL_QUERY_PPL, &Input, sizeof(Input), &Output,
                           sizeof(Output), &BytesReturned))
    return;

  wprintf(L"    ProcessId:      %u\n", Output.ProcessId);
  wprintf(L"    IsProtected:    %s\n", Output.IsProtected ? L"Yes" : L"No");

  if (Output.IsProtected) {
    wprintf(L"    ProtectionType: ");
    switch (Output.ProtectionType) {
    case 0:
      wprintf(L"None");
      break;
    case 1:
      wprintf(L"ProtectedLight");
      break;
    case 2:
      wprintf(L"Protected");
      break;
    default:
      wprintf(L"Unknown(%u)", Output.ProtectionType);
      break;
    }
    wprintf(L" (%u)\n", Output.ProtectionType);

    wprintf(L"    ProtectionSigner: ");
    switch (Output.ProtectionSigner) {
    case 0:
      wprintf(L"None");
      break;
    case 1:
      wprintf(L"Authenticode");
      break;
    case 2:
      wprintf(L"CodeGen");
      break;
    case 3:
      wprintf(L"Antimalware");
      break;
    case 4:
      wprintf(L"Lsa");
      break;
    case 5:
      wprintf(L"Windows");
      break;
    case 6:
      wprintf(L"WinTcb");
      break;
    case 7:
      wprintf(L"WinSystem");
      break;
    case 8:
      wprintf(L"App");
      break;
    default:
      wprintf(L"Unknown(%u)", Output.ProtectionSigner);
      break;
    }
    wprintf(L" (%u)\n", Output.ProtectionSigner);

    wprintf(L"    Audit:          %s\n", Output.Audit ? L"On" : L"Off");
    wprintf(L"    Raw Level:      0x%02X\n", Output.RawLevel);
  }
}

inline VOID SetCritical(ULONG ProcessId) {
  wprintf(L"[*] Setting PID=%u as critical process (terminate = BSOD) ...\n",
          ProcessId);
  wprintf(L"[!] WARNING: Killing this process will crash the system!\n");

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_SET_CRITICAL, &Input, sizeof(Input)))
    wprintf(L"[+] PID=%u is now a critical process.\n", ProcessId);
}

inline VOID RemoveCritical(ULONG ProcessId) {
  wprintf(L"[*] Removing critical process flag from PID=%u ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_REMOVE_CRITICAL, &Input, sizeof(Input)))
    wprintf(L"[+] PID=%u is no longer a critical process.\n", ProcessId);
}

inline VOID HideProcess(ULONG ProcessId) {
  wprintf(L"[*] Hiding PID=%u from task manager ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_HIDE_PROCESS, &Input, sizeof(Input)))
    wprintf(L"[+] PID=%u is now hidden.\n", ProcessId);
}

inline VOID UnhideProcess(ULONG ProcessId) {
  wprintf(L"[*] Unhiding PID=%u ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_UNHIDE_PROCESS, &Input, sizeof(Input)))
    wprintf(L"[+] PID=%u is now visible.\n", ProcessId);
}

inline VOID HideProcessCid(ULONG ProcessId) {
  wprintf(L"[*] Permanently hiding PID=%u (list unlink + PspCidTable removal) ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_HIDE_PROCESS_CID, &Input, sizeof(Input)))
    wprintf(L"[+] PID=%u is now permanently hidden.\n", ProcessId);
}

// 查询进程是否仍存活。返回 TRUE 表示 IOCTL 成功且 Alive 已填充；
// *Alive 为 TRUE 表示内核仍能定位该进程。对 CID 隐藏进程恒返回 FALSE。
inline BOOLEAN QueryProcessAliveKernel(ULONG ProcessId, BOOLEAN *Alive) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (Alive)
    *Alive = FALSE;

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  PROCESS_ALIVE_OUTPUT Output = {0};

  if (!SendIoctlWithOutput(IOCTL_QUERY_PROCESS_ALIVE, &Input, sizeof(Input),
                           &Output, sizeof(Output), nullptr))
    return FALSE;

  if (Alive)
    *Alive = Output.Alive;

  return TRUE;
}

inline BOOLEAN ForceDeleteFile(const WCHAR *FilePath) {
  if (FilePath == NULL || FilePath[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_NAME;
    return FALSE;
  }

  std::wstring NtPath(FilePath);
  for (wchar_t &Character : NtPath)
    if (Character == L'/')
      Character = L'\\';

  if (NtPath.rfind(L"\\??\\", 0) != 0 && NtPath.rfind(L"\\Device\\", 0) != 0) {
    if (NtPath.rfind(L"\\\\?\\", 0) == 0)
      NtPath = L"\\??\\" + NtPath.substr(4);
    else if (NtPath.rfind(L"\\\\", 0) == 0)
      NtPath = L"\\??\\UNC\\" + NtPath.substr(2);
    else if (NtPath.size() >= 2 && NtPath[1] == L':')
      NtPath = L"\\??\\" + NtPath;
    else {
      G_LastAegisCoreError = ERROR_INVALID_NAME;
      return FALSE;
    }
  }

  FORCE_DELETE_INPUT Input = {0};
  if (NtPath.size() >= _countof(Input.FilePath)) {
    G_LastAegisCoreError = ERROR_FILENAME_EXCED_RANGE;
    return FALSE;
  }

  wprintf(L"[*] Force deleting: %ls\n", NtPath.c_str());
  wcscpy_s(Input.FilePath, _countof(Input.FilePath), NtPath.c_str());

  const BOOLEAN Success =
      SendIoctl(IOCTL_FORCE_DELETE_FILE, &Input, sizeof(Input));
  if (Success)
    wprintf(L"[+] File marked for deletion.\n");
  return Success;
}

inline VOID AdjustPrivileges(ULONG ProcessId, const WCHAR *PrivName, BOOLEAN Enable) {
  wprintf(L"[*] %s privilege '%s' on PID=%u ...\n",
          Enable ? L"Enabling" : L"Disabling", PrivName, ProcessId);

  LUID Luid;
  if (!LookupPrivilegeValueW(NULL, PrivName, &Luid)) {
    wprintf(L"[!] Unknown privilege name: %s (error %u)\n", PrivName,
            GetLastError());
    return;
  }

  PRIVILEGE_ADJUST_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.PrivilegeLuid = Luid;
  Input.Enable = Enable;

  if (SendIoctl(IOCTL_ADJUST_PRIVILEGES, &Input, sizeof(Input)))
    wprintf(L"[+] Privilege adjusted.\n");
}

inline VOID QueueApc(ULONG ProcessId, ULONG Action) {
  wprintf(L"[*] Queuing APC to PID=%u (action=%u) ...\n", ProcessId, Action);

  APC_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.ApcAction = Action;

  if (SendIoctl(IOCTL_QUEUE_APC, &Input, sizeof(Input)))
    wprintf(L"[+] APC queued to PID=%u.\n", ProcessId);
}

inline VOID DisableApc(ULONG ProcessId) {
  wprintf(L"[*] Disabling APC delivery for PID=%u ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_DISABLE_APC, &Input, sizeof(Input)))
    wprintf(L"[+] APCs disabled for PID=%u.\n", ProcessId);
}

inline VOID EnableApc(ULONG ProcessId) {
  wprintf(L"[*] Enabling APC delivery for PID=%u ...\n", ProcessId);

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;

  if (SendIoctl(IOCTL_ENABLE_APC, &Input, sizeof(Input)))
    wprintf(L"[+] APCs re-enabled for PID=%u.\n", ProcessId);
}

inline BOOLEAN KillThread(ULONG ThreadId, ULONG ProcessId) {
  wprintf(L"[*] Terminating TID=%u in PID=%u via AegisCore ...\n", ThreadId,
          ProcessId);

  TERMINATE_THREAD_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.ThreadId = ThreadId;

  if (!SendIoctl(IOCTL_TERMINATE_THREAD, &Input, sizeof(Input)))
    return FALSE;

  for (int Attempt = 0; Attempt < 20; ++Attempt) {
    HANDLE Thread =
        OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
    if (Thread == NULL) {
      G_LastAegisCoreError = ERROR_SUCCESS;
      wprintf(L"[+] TID=%u terminated.\n", ThreadId);
      return TRUE;
    }

    DWORD ExitCode = STILL_ACTIVE;
    const BOOL ExitCodeOk = GetExitCodeThread(Thread, &ExitCode);
    CloseHandle(Thread);
    if (ExitCodeOk && ExitCode != STILL_ACTIVE) {
      G_LastAegisCoreError = ERROR_SUCCESS;
      wprintf(L"[+] TID=%u terminated (exit code %u).\n", ThreadId, ExitCode);
      return TRUE;
    }

    Sleep(25);
  }

  G_LastAegisCoreError = WAIT_TIMEOUT;
  wprintf(L"[!] TID=%u did not terminate within the verification window.\n",
          ThreadId);
  return FALSE;
}

inline BOOLEAN EnumerateThreadsAll(PTHREAD_ENUM_OUTPUT Output, ULONG Cursor) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  ZeroMemory(Output, sizeof(THREAD_ENUM_OUTPUT));
  THREAD_ENUM_INPUT Input = {};
  Input.Size = sizeof(THREAD_ENUM_INPUT);
  Input.Version = THREAD_ENUM_VERSION;
  Input.Cursor = Cursor;
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_ENUM_THREADS_ALL, &Input, sizeof(Input),
                           Output, sizeof(THREAD_ENUM_OUTPUT), &BytesReturned))
    return FALSE;
  if (BytesReturned < offsetof(THREAD_ENUM_OUTPUT, Entries) ||
      BytesReturned > sizeof(*Output) ||
      Output->Version != THREAD_ENUM_VERSION ||
      Output->Count > THREAD_ENUM_BATCH_SIZE ||
      Output->Count > (BytesReturned - offsetof(THREAD_ENUM_OUTPUT, Entries)) /
                          sizeof(THREAD_ENUM_ENTRY) ||
      (Output->NextCursor != 0 &&
       (Output->Count == 0 || Output->NextCursor <= Cursor))) {
    ZeroMemory(Output, sizeof(*Output));
    G_LastAegisCoreError = ERROR_INVALID_DATA;
    return FALSE;
  }
  return TRUE;
}

inline BOOLEAN SuspendThreadKernel(ULONG ThreadId) {
  THREAD_ID_INPUT Input = {};
  Input.ThreadId = ThreadId;
  return SendIoctl(IOCTL_THREAD_SUSPEND, &Input, sizeof(Input));
}

inline BOOLEAN ResumeThreadKernel(ULONG ThreadId) {
  THREAD_ID_INPUT Input = {};
  Input.ThreadId = ThreadId;
  return SendIoctl(IOCTL_THREAD_RESUME, &Input, sizeof(Input));
}

inline BOOLEAN SetThreadPreviousMode(ULONG ThreadId, UCHAR PreviousMode) {
  THREAD_PREVIOUS_MODE_INPUT Input = {};
  Input.ThreadId = ThreadId;
  Input.PreviousMode = PreviousMode;
  return SendIoctl(IOCTL_SET_THREAD_PREVIOUS_MODE, &Input, sizeof(Input));
}

inline BOOLEAN SetThreadApcQueueable(ULONG ThreadId, UCHAR Value) {
  THREAD_APC_QUEUEABLE_INPUT Input = {};
  Input.ThreadId = ThreadId;
  Input.Value = Value;
  return SendIoctl(IOCTL_SET_THREAD_APC_QUEUEABLE, &Input, sizeof(Input));
}

inline BOOLEAN KillProcessByThreads(
    ULONG ProcessId, TERMINATE_PROCESS_THREADS_OUTPUT &Output) {
  ZeroMemory(&Output, sizeof(Output));
  Output.ProcessId = ProcessId;

  TERMINATE_PROCESS_THREADS_INPUT Input = {};
  Input.ProcessId = ProcessId;
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_TERMINATE_PROCESS_THREADS, &Input,
                           sizeof(Input), &Output, sizeof(Output),
                           &BytesReturned))
    return FALSE;

  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output.LastStatus);
  wprintf(L"[*] Terminated %u/%u threads in PID=%u (failed=%u).\n",
          Output.TerminatedCount, Output.EnumeratedCount, ProcessId,
          Output.FailedCount);
  if (Output.TerminatedCount == 0 || Output.FailedCount != 0)
    return FALSE;

  for (int Attempt = 0; Attempt < 20; ++Attempt) {
    HANDLE Process =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (Process == NULL) {
      if (GetLastError() == ERROR_INVALID_PARAMETER) {
        G_LastAegisCoreError = ERROR_SUCCESS;
        return TRUE;
      }
    } else {
      DWORD ExitCode = STILL_ACTIVE;
      const BOOL ExitCodeOk = GetExitCodeProcess(Process, &ExitCode);
      CloseHandle(Process);
      if (ExitCodeOk && ExitCode != STILL_ACTIVE) {
        G_LastAegisCoreError = ERROR_SUCCESS;
        return TRUE;
      }
    }
    Sleep(25);
  }

  G_LastAegisCoreError = WAIT_TIMEOUT;
  return FALSE;
}

inline BOOLEAN DllInjectApc(ULONG ProcessId, const WCHAR *DllPath) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (DllPath == NULL || DllPath[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DLL_INJECT_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  wcsncpy_s(Input.DllPath, 260, DllPath, _TRUNCATE);

  const BOOLEAN Success =
      SendIoctl(IOCTL_DLL_INJECT_APC, &Input, sizeof(Input));
  if (Success)
    wprintf(L"[+] APC DLL injection queued to PID=%u: %s\n", ProcessId,
            DllPath);
  return Success;
}

inline BOOLEAN DllInjectThread(ULONG ProcessId, const WCHAR *DllPath) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (DllPath == NULL || DllPath[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DLL_INJECT_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  wcsncpy_s(Input.DllPath, 260, DllPath, _TRUNCATE);

  const BOOLEAN Success =
      SendIoctl(IOCTL_DLL_INJECT_THREAD, &Input, sizeof(Input));
  if (Success)
    wprintf(L"[+] Remote thread DLL injection launched in PID=%u: %s\n",
            ProcessId, DllPath);
  return Success;
}

inline VOID ClearAllProtection() {
  wprintf(L"[*] Clearing all protection lists ...\n");

  if (SendIoctl(IOCTL_CLEAR_ALL_PROTECTION, NULL, 0))
    wprintf(L"[+] All protection lists cleared.\n");
}

inline VOID RemoveAllObCallbacks() {
  wprintf(L"[*] Removing all Ob (Process/Thread) callbacks ...\n");

  if (SendIoctl(IOCTL_REMOVE_ALL_OBCALLBACKS, NULL, 0))
    wprintf(L"[+] All Ob callbacks removed.\n");
}

inline VOID RemoveAllRegistryCallbacks() {
  wprintf(L"[*] Removing all registry callbacks ...\n");

  if (SendIoctl(IOCTL_REMOVE_ALL_REGISTRYCALLBACKS, NULL, 0))
    wprintf(L"[+] All registry callbacks removed.\n");
}

inline VOID RemoveAllFilters() {
  wprintf(L"[*] Removing all minifilters ...\n");

  if (SendIoctl(IOCTL_REMOVE_ALL_FILTERS, NULL, 0))
    wprintf(L"[+] All minifilters removed.\n");
}

inline VOID EnumCallbacks() {
  wprintf(L"[*] Enumerating all registered callbacks ...\n\n");

  DWORD BytesReturned = 0;
  ULONG Count = 0;

  if (!SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, NULL, 0, &Count, sizeof(Count),
                           &BytesReturned)) {
    wprintf(L"[!] Failed to query callback count.\n");
    return;
  }

  if (Count == 0) {
    wprintf(L"[*] No callbacks registered.\n");
    return;
  }

  wprintf(L"[*] Found %u callback(s).\n\n", Count);

  DWORD BufferSize =
      sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
  PCALLBACK_ENUM_OUTPUT Out = (PCALLBACK_ENUM_OUTPUT)malloc(BufferSize);
  if (Out == NULL) {
    wprintf(L"[!] Memory allocation failed.\n");
    return;
  }
  ZeroMemory(Out, BufferSize);

  if (!SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, NULL, 0, Out, BufferSize,
                           &BytesReturned)) {
    wprintf(L"[!] Failed to enumerate callbacks.\n");
    free(Out);
    return;
  }

  wprintf(L"  %-10s %-18s  %-16s  %s\n", L"Type", L"Address", L"Module",
          L"Source");
  wprintf(L"  %-10s %-18s  %-16s  %s\n", L"----------", L"------------------",
          L"----------------", L"------");

  for (ULONG i = 0; i < Out->Count; i++) {
    PCALLBACK_ENTRY Entry = &Out->Entries[i];
    const WCHAR *TypeStr;

    switch (Entry->Type) {
    case CALLBACK_TYPE_OB_PROCESS:
      TypeStr = L"ObProc";
      break;
    case CALLBACK_TYPE_OB_THREAD:
      TypeStr = L"ObThread";
      break;
    case CALLBACK_TYPE_REGISTRY:
      TypeStr = L"Reg";
      break;
    case CALLBACK_TYPE_FLT_PRE_CREATE:
      TypeStr = L"FltCreate";
      break;
    case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION:
      TypeStr = L"FltSetInfo";
      break;
    case CALLBACK_TYPE_FLT_PRE_WRITE:
      TypeStr = L"FltWrite";
      break;
    case CALLBACK_TYPE_FLT_PRE_READ:
      TypeStr = L"FltRead";
      break;
    case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION:
      TypeStr = L"FltQueryInfo";
      break;
    case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL:
      TypeStr = L"FltDirCtrl";
      break;
    case CALLBACK_TYPE_FLT_PRE_CLEANUP:
      TypeStr = L"FltCleanup";
      break;
    case CALLBACK_TYPE_FLT_PRE_CLOSE:
      TypeStr = L"FltClose";
      break;
    case CALLBACK_TYPE_FLT_POST_CREATE:
      TypeStr = L"FltPostCreate";
      break;
    case CALLBACK_TYPE_FLT_POST_READ:
      TypeStr = L"FltPostRead";
      break;
    case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION:
      TypeStr = L"FltPostQuery";
      break;
    case CALLBACK_TYPE_FLT_POST_SET_INFORMATION:
      TypeStr = L"FltPostSet";
      break;
    case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL:
      TypeStr = L"FltPostDir";
      break;
    case CALLBACK_TYPE_FLT_POST_WRITE:
      TypeStr = L"FltPostWrite";
      break;
    case CALLBACK_TYPE_FLT_POST_CLEANUP:
      TypeStr = L"FltPostCleanup";
      break;
    case CALLBACK_TYPE_FLT_POST_CLOSE:
      TypeStr = L"FltPostClose";
      break;
    case CALLBACK_TYPE_PS_PROCESS_NOTIFY:
      TypeStr = L"PsProcess";
      break;
    case CALLBACK_TYPE_PS_THREAD_NOTIFY:
      TypeStr = L"PsThread";
      break;
    case CALLBACK_TYPE_PS_IMAGE_NOTIFY:
      TypeStr = L"PsImage";
      break;
    case CALLBACK_TYPE_BUGCHECK:
      TypeStr = L"BugCheck";
      break;
    case CALLBACK_TYPE_SHUTDOWN:
      TypeStr = L"Shutdown";
      break;
    case CALLBACK_TYPE_BUGCHECK_REASON:
      TypeStr = L"BugChkReason";
      break;
    default:
      TypeStr = L"Unknown";
      break;
    }

    wprintf(L"  %-10s 0x%016llX  %-16s  %s\n", TypeStr,
            (unsigned long long)Entry->Address,
            Entry->ModuleName[0] ? Entry->ModuleName : L"(unknown)",
            Entry->SourceName[0] ? Entry->SourceName : L"(unknown)");
  }

  wprintf(L"\n[+] Enumeration complete.\n");
  free(Out);
}

inline VOID RemoveCallbackByAddress(const WCHAR *AddrStr) {
  ULONG_PTR Address = wcstoull(AddrStr, NULL, 16);
  if (Address == 0) {
    wprintf(L"[!] Invalid address: %s\n", AddrStr);
    return;
  }

  wprintf(L"[!] CLI remove by address is no longer safe without a callback "
          L"type.\n");
  wprintf(L"    Address parsed: 0x%016llX\n", (unsigned long long)Address);
}

static ULONG ResolveAccountPid(ULONG AccountType) {
  if (AccountType == ACCOUNT_TYPE_SYSTEM)
    return 4;

  if (AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER) {
    ULONG Pid = 0;
    if (!EnsureTrustedInstallerRunning(&Pid))
      return 0;
    return Pid;
  }

  return 0;
}

inline BOOLEAN SetToken(ULONG SourcePid, ULONG TargetPid) {
  if (SourcePid == 0 || TargetPid == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  STEAL_TOKEN_INPUT Input = {0};
  Input.SourceProcessId = SourcePid;
  Input.TargetProcessId = TargetPid;

  return SendIoctl(IOCTL_STEAL_TOKEN, &Input, sizeof(Input));
}

inline BOOLEAN SetTokenAs(ULONG AccountType, ULONG TargetPid,
                   PULONG OutSourcePid = NULL) {
  ULONG AccountPid = ResolveAccountPid(AccountType);
  if (AccountPid == 0) {
    G_LastAegisCoreError = ERROR_NOT_FOUND;
    return FALSE;
  }

  if (OutSourcePid)
    *OutSourcePid = AccountPid;
  return SetToken(AccountPid, TargetPid);
}

static BOOLEAN ConvertLaunchPathToWin32Path(const WCHAR *ImagePath,
                                            std::wstring &Win32Path) {
  Win32Path.clear();
  if (ImagePath == NULL || ImagePath[0] == L'\0')
    return FALSE;

  const std::wstring Path(ImagePath);
  if (Path.size() >= 4 && _wcsnicmp(Path.c_str(), L"\\??\\", 4) == 0) {
    Win32Path = Path.substr(4);
    return !Win32Path.empty();
  }

  if (Path.size() >= 12 &&
      _wcsnicmp(Path.c_str(), L"\\Device\\Mup\\", 12) == 0) {
    Win32Path = L"\\\\";
    Win32Path.append(Path.substr(12));
    return TRUE;
  }

  if (Path.size() >= 12 &&
      _wcsnicmp(Path.c_str(), L"\\SystemRoot\\", 12) == 0) {
    WCHAR WindowsDir[MAX_PATH] = {};
    if (GetWindowsDirectoryW(WindowsDir, ARRAYSIZE(WindowsDir)) == 0)
      return FALSE;

    Win32Path.assign(WindowsDir);
    if (!Win32Path.empty() && Win32Path.back() != L'\\')
      Win32Path.push_back(L'\\');
    Win32Path.append(Path.substr(12));
    return TRUE;
  }

  if (Path.size() >= 3 && Path[1] == L':' &&
      (Path[2] == L'\\' || Path[2] == L'/')) {
    Win32Path = Path;
    return TRUE;
  }

  WCHAR Drives[512] = {};
  const DWORD DriveLength = GetLogicalDriveStringsW(ARRAYSIZE(Drives), Drives);
  if (DriveLength == 0 || DriveLength >= ARRAYSIZE(Drives))
    return FALSE;

  for (const WCHAR *Drive = Drives; *Drive != L'\0';
       Drive += wcslen(Drive) + 1) {
    if (wcslen(Drive) < 2 || Drive[1] != L':')
      continue;

    WCHAR DeviceName[512] = {};
    WCHAR DriveName[3] = {Drive[0], L':', L'\0'};
    if (QueryDosDeviceW(DriveName, DeviceName, ARRAYSIZE(DeviceName)) == 0)
      continue;

    const size_t PrefixLength = wcslen(DeviceName);
    if (_wcsnicmp(Path.c_str(), DeviceName, PrefixLength) != 0)
      continue;

    if (Path.size() > PrefixLength && Path[PrefixLength] != L'\\' &&
        Path[PrefixLength] != L'/')
      continue;

    Win32Path.assign(DriveName);
    Win32Path.append(Path.substr(PrefixLength));
    return TRUE;
  }

  return FALSE;
}

inline BOOLEAN LaunchAs(ULONG AccountType, const WCHAR *ImagePath,
                 PULONG OutProcessId = NULL) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (OutProcessId)
    *OutProcessId = 0;
  if (ImagePath == NULL || ImagePath[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  if (AccountType != ACCOUNT_TYPE_SYSTEM &&
      AccountType != ACCOUNT_TYPE_TRUSTEDINSTALLER) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  if (AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER) {
    ULONG TrustedInstallerPid = 0;
    if (!EnsureTrustedInstallerRunning(&TrustedInstallerPid) ||
        TrustedInstallerPid == 0) {
      G_LastAegisCoreError = ERROR_NOT_FOUND;
      return FALSE;
    }
  }

  std::wstring Win32Path;
  if (!ConvertLaunchPathToWin32Path(ImagePath, Win32Path)) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  std::wstring CommandLine = L"\"";
  CommandLine.append(Win32Path);
  CommandLine.push_back(L'"');

  std::vector<WCHAR> MutableCommandLine(CommandLine.begin(), CommandLine.end());
  MutableCommandLine.push_back(L'\0');

  const size_t Slash = Win32Path.find_last_of(L"\\/");
  const std::wstring WorkingDirectory =
      Slash == std::wstring::npos ? std::wstring() : Win32Path.substr(0, Slash);

  STARTUPINFOW StartupInfo = {};
  PROCESS_INFORMATION ProcessInfo = {};
  StartupInfo.cb = sizeof(StartupInfo);
  StartupInfo.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
  StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  StartupInfo.wShowWindow = SW_SHOWNORMAL;

  const BOOL Created =
      CreateProcessW(Win32Path.c_str(), MutableCommandLine.data(), NULL, NULL,
                     FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL,
                     WorkingDirectory.empty() ? NULL : WorkingDirectory.c_str(),
                     &StartupInfo, &ProcessInfo);
  if (!Created) {
    G_LastAegisCoreError = GetLastError();
    return FALSE;
  }

  const DWORD ResumeResult = ResumeThread(ProcessInfo.hThread);
  if (ResumeResult == static_cast<DWORD>(-1)) {
    G_LastAegisCoreError = GetLastError();
    TerminateProcess(ProcessInfo.hProcess,
                     static_cast<UINT>(G_LastAegisCoreError));
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return FALSE;
  }

  AllowSetForegroundWindow(ProcessInfo.dwProcessId);
  WaitForInputIdle(ProcessInfo.hProcess, 2000);
  Sleep(250);

  if (!SetTokenAs(AccountType, ProcessInfo.dwProcessId)) {
    const DWORD TokenError = G_LastAegisCoreError != ERROR_SUCCESS
                                 ? G_LastAegisCoreError
                                 : ERROR_ACCESS_DENIED;
    TerminateProcess(ProcessInfo.hProcess, static_cast<UINT>(TokenError));
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    G_LastAegisCoreError = TokenError;
    return FALSE;
  }

  if (OutProcessId)
    *OutProcessId = ProcessInfo.dwProcessId;
  CloseHandle(ProcessInfo.hThread);
  CloseHandle(ProcessInfo.hProcess);
  return TRUE;
}

inline BOOLEAN ReadMemory(ULONG ProcessId, ULONG_PTR Address, PVOID Buffer, ULONG Size,
                   PULONG BytesRead) {
  if (BytesRead)
    *BytesRead = 0;
  if (Buffer == NULL || Size == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD BufSz = sizeof(MEMORY_READ_INPUT) + Size;
  PMEMORY_READ_INPUT Input = (PMEMORY_READ_INPUT)malloc(BufSz);
  if (Input == NULL) {
    G_LastAegisCoreError = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }

  ZeroMemory(Input, BufSz);
  Input->ProcessId = ProcessId;
  Input->Address = Address;
  Input->Size = Size;

  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_READ_MEMORY, Input, sizeof(MEMORY_READ_INPUT),
                          Input, BufSz, &BytesReturned);

  if (Success && BytesReturned > sizeof(MEMORY_READ_INPUT)) {
    ULONG ActualRead = BytesReturned - sizeof(MEMORY_READ_INPUT);
    CopyMemory(Buffer, (PUCHAR)Input + sizeof(MEMORY_READ_INPUT), ActualRead);
    if (BytesRead)
      *BytesRead = ActualRead;
  }

  free(Input);
  return Success;
}

inline BOOLEAN WriteMemory(ULONG ProcessId, ULONG_PTR Address, PVOID Buffer,
                    ULONG Size) {
  if (Buffer == NULL || Size == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD BufSz = sizeof(MEMORY_WRITE_INPUT) + Size;
  PMEMORY_WRITE_INPUT Input = (PMEMORY_WRITE_INPUT)malloc(BufSz);
  if (Input == NULL) {
    G_LastAegisCoreError = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }

  Input->ProcessId = ProcessId;
  Input->Address = Address;
  Input->Size = Size;
  CopyMemory((PUCHAR)Input + sizeof(MEMORY_WRITE_INPUT), Buffer, Size);

  BOOLEAN Success = SendIoctl(IOCTL_WRITE_MEMORY, Input, BufSz);
  free(Input);
  return Success;
}

inline BOOLEAN QuerySystemTables(PSYSTEM_TABLES_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  ZeroMemory(Output, sizeof(SYSTEM_TABLES_OUTPUT));
  DWORD BytesReturned = 0;

  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_QUERY_SYSTEM_TABLES, NULL, 0, Output,
                          sizeof(SYSTEM_TABLES_OUTPUT), &BytesReturned);
  return Success;
}

inline BOOLEAN QuerySystemTableEntries(ULONG TableKind,
                                PSYSTEM_TABLE_ENTRIES_OUTPUT Output) {
  if (Output == NULL || TableKind > SYSTEM_TABLE_KIND_GDT) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  ZeroMemory(Output, sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT));
  Output->TableKind = TableKind;
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(
      IOCTL_ENUM_SYSTEM_TABLE_ENTRIES, Output, sizeof(ULONG), Output,
      sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT), &BytesReturned);
}

inline BOOLEAN QueryPiDDBCacheEntries(PPIDDB_CACHE_ENUM_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  ZeroMemory(Output, sizeof(PIDDB_CACHE_ENUM_OUTPUT));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_PIDDB_CACHE, nullptr, 0, Output,
                             sizeof(PIDDB_CACHE_ENUM_OUTPUT), &BytesReturned);
}

inline BOOLEAN QueryHalDispatchEntries(ULONG TableKind,
                                PSYSTEM_TABLE_ENTRIES_OUTPUT Output) {
  if (Output == NULL ||
      (TableKind != HAL_DISPATCH_TABLE_KIND_PUBLIC &&
       TableKind != HAL_DISPATCH_TABLE_KIND_PRIVATE)) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  ZeroMemory(Output, sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT));
  Output->TableKind = TableKind;
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(
      IOCTL_ENUM_HAL_DISPATCH, Output, sizeof(ULONG), Output,
      sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT), &BytesReturned);
}

inline BOOLEAN EnumerateDpcQueue(PDPC_ENUM_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  ZeroMemory(Output, sizeof(DPC_ENUM_OUTPUT));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_DPC, nullptr, 0, Output,
                             sizeof(DPC_ENUM_OUTPUT), &BytesReturned);
}

inline BOOLEAN EnumerateHotkeys(PHOTKEY_ENUM_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  ZeroMemory(Output, sizeof(HOTKEY_ENUM_OUTPUT));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_HOTKEYS, nullptr, 0, Output,
                             sizeof(HOTKEY_ENUM_OUTPUT), &BytesReturned);
}

inline BOOLEAN RemoveHotkey(const HOTKEY_ENUM_ENTRY& Entry, NTSTATUS* KernelStatus,
                     DWORD* ErrorCode, ULONG* Detail = nullptr,
                     HOTKEY_REMOVE_DIAGNOSTIC* Diagnostic = nullptr) {
  if (!KernelStatus || !ErrorCode) return FALSE;
  *KernelStatus = static_cast<NTSTATUS>(0xC0000001u);
  *ErrorCode = ERROR_SUCCESS;
  if (Detail) *Detail = HOTKEY_REMOVE_DETAIL_NONE;
  if (Diagnostic) ZeroMemory(Diagnostic, sizeof(*Diagnostic));
  // 初始化当前后台线程的 USER 上下文，再同步发�?IOCTL�?
  MSG Message{};
  PeekMessageW(&Message, nullptr, 0, 0, PM_NOREMOVE);
  HOTKEY_REMOVE_INPUT Input{sizeof(HOTKEY_REMOVE_INPUT), 1, Entry};
  HOTKEY_REMOVE_OUTPUT Output{};
  DWORD BytesReturned = 0;
  std::lock_guard<std::mutex> Lock(G_DeviceMutex);
  if (!OpenDeviceSilent()) {
    *ErrorCode = GetLastError();
    return FALSE;
  }
  const BOOL Ok = DeviceIoControl(G_DeviceHandle, IOCTL_REMOVE_HOTKEY, &Input,
      sizeof(Input), &Output, sizeof(Output), &BytesReturned, nullptr);
  const DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
  CloseDevice();
  // 旧驱动返回 8 字节；成功结果仍有效，失败时明确提示重载而非误报布局不支持。
  if (Ok && BytesReturned == 8 && Output.Size == 8) {
    *KernelStatus = Output.KernelStatus;
    if (Output.KernelStatus >= 0) return TRUE;
    *ErrorCode = ERROR_REVISION_MISMATCH;
    return FALSE;
  }
  if (Ok && BytesReturned == 12 && Output.Size == 12) {
    *KernelStatus = Output.KernelStatus;
    if (Detail) *Detail = Output.Detail;
    if (Output.KernelStatus >= 0) return TRUE;
    *ErrorCode = ERROR_REVISION_MISMATCH;
    return FALSE;
  }
  if (!Ok || BytesReturned != sizeof(Output) || Output.Size != sizeof(Output)) {
    *ErrorCode = Ok ? ERROR_INVALID_DATA : Error;
    return FALSE;
  }
  *KernelStatus = Output.KernelStatus;
  if (Detail) *Detail = Output.Detail;
  if (Diagnostic) *Diagnostic = Output.Diagnostic;
  return Output.KernelStatus >= 0;
}

inline BOOLEAN RemoveDpcEntry(ULONG_PTR DpcObject, ULONG Cpu) {
  if (DpcObject == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  DPC_REMOVE_INPUT Input{};
  Input.DpcObject = DpcObject;
  Input.Cpu = Cpu;
  return SendIoctl(IOCTL_REMOVE_DPC, &Input, sizeof(Input));
}

inline BOOLEAN RemovePiDDBCacheEntry(ULONG_PTR EntryAddress) {
  if (EntryAddress == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  PIDDB_REMOVE_INPUT Input{};
  Input.EntryAddress = EntryAddress;
  return SendIoctl(IOCTL_REMOVE_PIDDB_ENTRY, &Input, sizeof(Input));
}

inline DWORD AegisCoreNtStatusToWin32(NTSTATUS Status) {
  return Status == 0 ? ERROR_SUCCESS
                     : (DWORD)RtlNtStatusToDosError(Status);
}

inline BOOLEAN QueryDriverEntries(std::vector<DRIVER_ENUM_ENTRY> &Entries,
                           PDRIVER_ENUM_HEADER Header = NULL) {
  Entries.clear();
  if (Header != NULL)
    ZeroMemory(Header, sizeof(*Header));

  DRIVER_ENUM_HEADER Probe{};
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_ENUM_DRIVERS, NULL, 0, &Probe, sizeof(Probe),
                           &BytesReturned))
    return FALSE;

  G_LastAegisCoreDetails.assign(Probe.Message);
  if (Header != NULL)
    *Header = Probe;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Probe.NtStatus);
  if (Probe.NtStatus != 0 || Probe.Count == 0)
    return Probe.NtStatus == 0;

  const size_t BufferSize =
      sizeof(DRIVER_ENUM_HEADER) +
      (static_cast<size_t>(Probe.Count) * sizeof(DRIVER_ENUM_ENTRY));
  PDRIVER_ENUM_OUTPUT Output =
      static_cast<PDRIVER_ENUM_OUTPUT>(malloc(BufferSize));
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }

  ZeroMemory(Output, BufferSize);
  const BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_ENUM_DRIVERS, NULL, 0, Output,
                          static_cast<DWORD>(BufferSize), &BytesReturned);
  if (Success) {
    G_LastAegisCoreDetails.assign(Output->Header.Message);
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Header.NtStatus);
    if (Output->Header.NtStatus == 0)
      Entries.assign(Output->Entries, Output->Entries + Output->Header.Count);
  }

  free(Output);
  return Success && G_LastAegisCoreError == ERROR_SUCCESS;
}

inline bool QueryAegisCoreCapabilities(INVENTORY_CAPABILITIES_OUTPUT *Output) {
  if (Output == nullptr) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return false;
  }
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_QUERY_CAPABILITIES, nullptr, 0, Output,
                           sizeof(*Output), &BytesReturned))
    return false;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Header.Status);
  return Output->Header.Version == INVENTORY_PROTOCOL_VERSION &&
         Output->Header.Status == 0;
}

inline bool QueryAegisCoreRecords(DWORD Ioctl, const INVENTORY_QUERY_INPUT &Request,
                                   std::vector<INVENTORY_RECORD> &Records,
                                   INVENTORY_LIST_HEADER *ResultHeader = nullptr) {
  Records.clear();
  INVENTORY_QUERY_INPUT Input = Request;
  Input.Size = sizeof(Input);
  Input.Version = INVENTORY_PROTOCOL_VERSION;
  if (Input.MaxEntries == 0 || Input.MaxEntries > INVENTORY_MAX_PAGE_RECORDS)
    Input.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;

  INVENTORY_LIST_HEADER LastHeader{};
  ULONG64 Cursor = Input.Cursor;
  for (ULONG Page = 0; Page < 4096; ++Page) {
    Input.Cursor = Cursor;
    const size_t BufferSize =
        FIELD_OFFSET(INVENTORY_LIST_OUTPUT, Records) +
        static_cast<size_t>(Input.MaxEntries) * sizeof(INVENTORY_RECORD);
    std::vector<unsigned char> Buffer(BufferSize);
    DWORD BytesReturned = 0;
    if (!SendIoctlWithOutput(Ioctl, &Input, sizeof(Input), Buffer.data(),
                             static_cast<DWORD>(Buffer.size()), &BytesReturned))
      return false;
    if (BytesReturned < sizeof(INVENTORY_LIST_HEADER)) {
      G_LastAegisCoreError = ERROR_INVALID_DATA;
      return false;
    }
    const auto *Output =
        reinterpret_cast<const INVENTORY_LIST_OUTPUT *>(Buffer.data());
    LastHeader = Output->Header;
    if (LastHeader.Version != INVENTORY_PROTOCOL_VERSION ||
        LastHeader.ReturnedCount > Input.MaxEntries ||
        FIELD_OFFSET(INVENTORY_LIST_OUTPUT, Records) +
                static_cast<size_t>(LastHeader.ReturnedCount) *
                    sizeof(INVENTORY_RECORD) >
            BytesReturned) {
      G_LastAegisCoreError = ERROR_INVALID_DATA;
      return false;
    }
    Records.insert(Records.end(), Output->Records,
                   Output->Records + LastHeader.ReturnedCount);
    if (LastHeader.NextCursor == 0 || LastHeader.NextCursor == Cursor)
      break;
    Cursor = LastHeader.NextCursor;
  }
  if (ResultHeader != nullptr)
    *ResultHeader = LastHeader;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(LastHeader.Status);
  return LastHeader.Version == INVENTORY_PROTOCOL_VERSION;
}

inline bool QueryProcessRecords(ULONG ProcessId, DWORD Ioctl,
                                  std::vector<INVENTORY_RECORD> &Records,
                                  INVENTORY_LIST_HEADER *Header = nullptr) {
  INVENTORY_QUERY_INPUT Request{};
  Request.ProcessId = ProcessId;
  Request.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;
  return QueryAegisCoreRecords(Ioctl, Request, Records, Header);
}

inline bool QueryNamedDriverRecords(const std::wstring &DriverName,
                                      std::vector<INVENTORY_RECORD> &Records,
                                      INVENTORY_LIST_HEADER *Header = nullptr) {
  INVENTORY_QUERY_INPUT Request{};
  Request.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;
  // 内核查询接受驱动对象名，但会自行补上 "\\Driver\\" 命名空间前缀�?
  // 调用方可能传服务名或已限定的对象路径，因此这里统一做规范化�?
  std::wstring Normalized = DriverName;
  while (!Normalized.empty() &&
         (Normalized.front() == L' ' || Normalized.front() == L'\t'))
    Normalized.erase(Normalized.begin());
  constexpr wchar_t DriverPrefix[] = L"\\Driver\\";
  if (Normalized.size() >= _countof(DriverPrefix) - 1 &&
      _wcsnicmp(Normalized.c_str(), DriverPrefix,
                _countof(DriverPrefix) - 1) == 0)
    Normalized.erase(0, _countof(DriverPrefix) - 1);
  wcsncpy_s(Request.Name, Normalized.c_str(), _TRUNCATE);
  return QueryAegisCoreRecords(IOCTL_QUERY_DRIVER, Request, Records,
                                Header);
}

inline bool QueryHookCapabilities(HOOK_CAPABILITIES_OUTPUT *Output) {
  if (Output == nullptr) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return false;
  }
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  const BOOL Ok = SendIoctlWithOutput(IOCTL_HOOK_QUERY_CAPABILITIES, nullptr, 0,
                                      Output, sizeof(*Output), &BytesReturned);
  if (!Ok)
    return false;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->LastStatus);
  return Output->Version == HOOK_PROTOCOL_VERSION &&
         Output->Size >= sizeof(HOOK_CAPABILITIES_OUTPUT);
}

inline bool QueryHooks(std::vector<HOOK_RECORD> &Records) {
  Records.clear();
  ULONG Capacity = 64;
  for (int Attempt = 0; Attempt < 4; ++Attempt) {
    const size_t Bytes = FIELD_OFFSET(HOOK_ENUM_OUTPUT, Records) +
                         static_cast<size_t>(Capacity) * sizeof(HOOK_RECORD);
    std::vector<unsigned char> Buffer(Bytes);
    DWORD BytesReturned = 0;
    if (!SendIoctlWithOutput(IOCTL_HOOK_ENUM, nullptr, 0, Buffer.data(),
                             static_cast<DWORD>(Buffer.size()),
                             &BytesReturned))
      return false;
    if (BytesReturned < FIELD_OFFSET(HOOK_ENUM_OUTPUT, Records)) {
      G_LastAegisCoreError = ERROR_INVALID_DATA;
      return false;
    }
    const auto *Output = reinterpret_cast<const HOOK_ENUM_OUTPUT *>(Buffer.data());
    if (Output->Version != HOOK_PROTOCOL_VERSION || Output->Count > Capacity) {
      G_LastAegisCoreError = ERROR_INVALID_DATA;
      return false;
    }
    Records.assign(Output->Records, Output->Records + Output->Count);
    return true;
  }
  G_LastAegisCoreError = ERROR_INSUFFICIENT_BUFFER;
  return false;
}

inline bool OperateHook(HOOK_REQUEST Request, HOOK_RECORD *Result = nullptr) {
  Request.Size = sizeof(Request);
  Request.Version = HOOK_PROTOCOL_VERSION;
  if (Request.Operation == HOOK_OP_RESTORE_ALL) {
    const BOOL Ok = SendIoctl(IOCTL_HOOK_RESTORE_ALL, nullptr, 0);
    if (Result != nullptr)
      ZeroMemory(Result, sizeof(*Result));
    return Ok;
  }
  const DWORD Ioctl = Request.Operation == HOOK_OP_ENABLE
                          ? IOCTL_HOOK_ENABLE
                          : (Request.Operation == HOOK_OP_DISABLE
                                 ? IOCTL_HOOK_DISABLE
                                 : (Request.Operation == HOOK_OP_REMOVE
                                        ? IOCTL_HOOK_REMOVE
                                        : (Request.Operation == HOOK_OP_VERIFY
                                               ? IOCTL_HOOK_VERIFY
                                               : IOCTL_HOOK_INSTALL)));
  DWORD BytesReturned = 0;
  HOOK_RECORD Output{};
  const BOOL Ok = SendIoctlWithOutput(Ioctl, &Request,
                                      sizeof(Request), &Output, sizeof(Output),
                                      &BytesReturned);
  if (!Ok)
    return false;
  if (Result != nullptr)
    *Result = Output;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output.Status);
  return Output.Status >= 0;
}

inline bool OperateHookById(DWORD Ioctl, ULONG Operation, ULONG HookId,
                            HOOK_RECORD *Result = nullptr) {
  HOOK_REQUEST Request{};
  Request.Size = sizeof(Request);
  Request.Version = HOOK_PROTOCOL_VERSION;
  Request.Operation = Operation;
  Request.HookId = HookId;
  DWORD BytesReturned = 0;
  HOOK_RECORD Output{};
  const BOOL Ok = SendIoctlWithOutput(Ioctl, &Request, sizeof(Request), &Output,
                                      sizeof(Output), &BytesReturned);
  if (!Ok)
    return false;
  if (Result != nullptr)
    *Result = Output;
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output.Status);
  return Output.Status >= 0;
}

inline bool InstallDriverDispatchHook(const std::wstring &DriverName,
                                      ULONG MajorFunction,
                                      HOOK_RECORD *Result = nullptr) {
  HOOK_REQUEST Request{};
  Request.Operation = HOOK_OP_INSTALL;
  Request.TargetKind = HOOK_TARGET_DRIVER_DISPATCH;
  Request.MajorFunction = MajorFunction;
  wcsncpy_s(Request.DriverName, DriverName.c_str(), _TRUNCATE);
  return OperateHook(Request, Result);
}

inline bool QueryAdvancedRecords(ULONG Kind, ULONG ProcessId,
                                   ULONG TargetId, ULONG64 Cursor,
                                   std::vector<INVENTORY_RECORD> &Records,
                                   INVENTORY_LIST_HEADER *Header = nullptr) {
  INVENTORY_QUERY_INPUT Request{};
  Request.ProcessId = ProcessId;
  Request.TargetId = Kind;
  Request.Flags = TargetId;
  Request.Cursor = Cursor;
  Request.MaxEntries = INVENTORY_MAX_PAGE_RECORDS;
  return QueryAegisCoreRecords(IOCTL_QUERY_ADVANCED, Request, Records,
                                Header);
}

// PTE 页表遍历:TargetId=ADVANCED_KIND_PTE,虚拟地址�?Cursor 传入�?
inline bool QueryPteWalk(ULONG ProcessId, ULONG64 Address,
                          std::vector<INVENTORY_RECORD> &Records,
                          INVENTORY_LIST_HEADER *Header = nullptr) {
  return QueryAdvancedRecords(ADVANCED_KIND_PTE, ProcessId, 0, Address,
                              Records, Header);
}

inline bool AdvancedOperation(const ADVANCED_OPERATION_INPUT &Request,
                                ADVANCED_OPERATION_OUTPUT *Output) {
  if (Output == nullptr) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return false;
  }
  ADVANCED_OPERATION_INPUT Input = Request;
  Input.Size = sizeof(Input);
  Input.Version = 3;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_ADVANCED_OPERATION, &Input, sizeof(Input),
                           Output, sizeof(*Output), &BytesReturned))
    return false;
  if (BytesReturned != sizeof(*Output) || Output->Size != sizeof(*Output) ||
      Output->Version != 3) {
    G_LastAegisCoreError = ERROR_INVALID_DATA;
    return false;
  }
  G_LastAegisCoreDetails.assign(Output->Detail);
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Status);
  return Output->Status == 0;
}

inline bool CaptureAdvancedTransaction(ULONG Kind, ULONG TargetId,
                                         ULONG64 Address,
                                         ADVANCED_OPERATION_OUTPUT *Output) {
  ADVANCED_OPERATION_INPUT Input{};
  Input.Kind = Kind;
  Input.Operation = ADVANCED_OP_CAPTURE;
  Input.TargetId = TargetId;
  Input.Address = Address;
  return AdvancedOperation(Input, Output);
}

inline bool ApplyAdvancedTransaction(ULONG Kind, ULONG64 TransactionId,
                                       ULONG64 Value,
                                       ADVANCED_OPERATION_OUTPUT *Output) {
  ADVANCED_OPERATION_INPUT Input{};
  Input.Kind = Kind;
  Input.Operation = ADVANCED_OP_APPLY;
  Input.TransactionId = TransactionId;
  Input.Value = Value;
  return AdvancedOperation(Input, Output);
}

inline bool RollbackAdvancedTransaction(ULONG Kind, ULONG64 TransactionId,
                                          ADVANCED_OPERATION_OUTPUT *Output) {
  ADVANCED_OPERATION_INPUT Input{};
  Input.Kind = Kind;
  Input.Operation = ADVANCED_OP_ROLLBACK;
  Input.TransactionId = TransactionId;
  return AdvancedOperation(Input, Output);
}

inline BOOLEAN LoadDriverKernel(const WCHAR *ServiceName, const WCHAR *ImagePath,
                         PDRIVER_CONTROL_OUTPUT Output = NULL) {
  if (ServiceName == NULL || ServiceName[0] == L'\0' || ImagePath == NULL ||
      ImagePath[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DRIVER_CONTROL_INPUT Buffer{};
  wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);
  wcsncpy_s(Buffer.ImagePath, ImagePath, _TRUNCATE);

  DRIVER_CONTROL_OUTPUT Result{};
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_LOAD_DRIVER, &Buffer, sizeof(Buffer), &Result,
                           sizeof(Result), &BytesReturned))
    return FALSE;

  G_LastAegisCoreDetails.assign(Result.Message);
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.NtStatus);
  if (Output != NULL)
    *Output = Result;
  return Result.NtStatus == 0;
}

inline BOOLEAN UnloadDriverKernel(const WCHAR *ServiceName, BOOLEAN DeleteOnUnload,
                           PDRIVER_CONTROL_OUTPUT Output = NULL) {
  if (ServiceName == NULL || ServiceName[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DRIVER_CONTROL_INPUT Buffer{};
  wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);
  Buffer.DeleteOnUnload = DeleteOnUnload;

  DRIVER_CONTROL_OUTPUT Result{};
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_UNLOAD_DRIVER, &Buffer, sizeof(Buffer),
                           &Result, sizeof(Result), &BytesReturned))
    return FALSE;

  G_LastAegisCoreDetails.assign(Result.Message);
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.NtStatus);
  if (Output != NULL)
    *Output = Result;
  return Result.NtStatus == 0;
}

inline BOOLEAN HideDriverKernel(const WCHAR *ServiceName,
                         PDRIVER_HIDE_OUTPUT Output = NULL) {
  if (ServiceName == NULL || ServiceName[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DRIVER_HIDE_INPUT Buffer{};
  wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);

  DRIVER_HIDE_OUTPUT Result{};
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_HIDE_DRIVER, &Buffer, sizeof(Buffer), &Result,
                           sizeof(Result), &BytesReturned))
    return FALSE;

  G_LastAegisCoreDetails.assign(Result.Message);
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.NtStatus);
  if (Output != NULL)
    *Output = Result;
  return Result.NtStatus == 0;
}

inline BOOLEAN HideDriverKernelCid(const WCHAR *ServiceName,
                            PDRIVER_HIDE_OUTPUT Output = NULL) {
  if (ServiceName == NULL || ServiceName[0] == L'\0') {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DRIVER_HIDE_INPUT Buffer{};
  wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);

  DRIVER_HIDE_OUTPUT Result{};
  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_HIDE_DRIVER_CID, &Buffer, sizeof(Buffer),
                           &Result, sizeof(Result), &BytesReturned))
    return FALSE;

  G_LastAegisCoreDetails.assign(Result.Message);
  G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.NtStatus);
  if (Output != NULL)
    *Output = Result;
  return Result.NtStatus == 0;
}

// PreviousMode�? = KernelMode�? = UserMode
inline BOOLEAN SetProcessPreviousMode(ULONG ProcessId, UCHAR PreviousMode = 0) {
  if (PreviousMode > 1) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  CRITICAL_PROCESS_INPUT Input = {0};
  Input.ProcessId = ProcessId;
  Input.PreviousMode = PreviousMode;
  return SendIoctl(IOCTL_SET_PREVIOUS_MODE, &Input, sizeof(Input));
}

inline BOOLEAN KernelReadMemory(ULONG_PTR Address, PVOID Buffer, ULONG Size,
                         PULONG BytesRead,
                         KRNL_MEMRW_METHOD Method = KrnlMemRwAuto) {
  if (BytesRead)
    *BytesRead = 0;
  if (Buffer == NULL || Size == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD BufSz = sizeof(KERNEL_READ_OUTPUT) + Size;
  PKERNEL_READ_OUTPUT Output = (PKERNEL_READ_OUTPUT)malloc(BufSz);
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }
  ZeroMemory(Output, BufSz);

  KERNEL_READ_INPUT Input = {};
  Input.Address = Address;
  Input.Size = Size;
  Input.Method = Method;

  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_KERNEL_READ_MEMORY, &Input, sizeof(Input),
                          Output, BufSz, &BytesReturned);

  if (Success && BytesReturned > sizeof(KERNEL_READ_OUTPUT)) {
    ULONG ActualRead = Output->BytesRead;
    if (ActualRead > Size)
      ActualRead = Size;
    CopyMemory(Buffer, Output->Data, ActualRead);
    if (BytesRead)
      *BytesRead = ActualRead;
  } else if (Success && Output->Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Status);
    Success = FALSE;
  }

  free(Output);
  return Success;
}

inline BOOLEAN KernelWriteMemory(ULONG_PTR Address, PVOID Buffer, ULONG Size,
                          KRNL_MEMRW_METHOD Method = KrnlMemRwAuto) {
  if (Buffer == NULL || Size == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD BufSz = sizeof(KERNEL_WRITE_INPUT) + Size;
  PKERNEL_WRITE_INPUT Input = (PKERNEL_WRITE_INPUT)malloc(BufSz);
  if (Input == NULL) {
    G_LastAegisCoreError = ERROR_NOT_ENOUGH_MEMORY;
    return FALSE;
  }

  Input->Address = Address;
  Input->Size = Size;
  Input->Method = Method;
  CopyMemory((PUCHAR)Input + sizeof(KERNEL_WRITE_INPUT), Buffer, Size);

  BOOLEAN Success = SendIoctl(IOCTL_KERNEL_WRITE_MEMORY, Input, BufSz);
  free(Input);
  return Success;
}

/* ---- 内存区域控制 (IOCTL 0x881/0x882) ---- */
inline BOOL KernelProtectMemory(ULONG ProcessId, ULONG_PTR Address, ULONG64 Size,
                         ULONG NewProtect, ULONG *OldProtect) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  MEMORY_PROTECT_INPUT Input = {};
  Input.ProcessId = ProcessId;
  Input.Address = Address;
  Input.Size = Size;
  Input.NewProtect = NewProtect;
  MEMORY_PROTECT_OUTPUT Output = {};
  DWORD BytesReturned = 0;
  const BOOL Success =
      SendIoctlWithOutput(IOCTL_MEMORY_PROTECT, &Input, sizeof(Input),
                          &Output, sizeof(Output), &BytesReturned);
  if (OldProtect)
    *OldProtect = Output.OldProtect;
  return Success;
}

inline BOOL KernelAllocMemory(ULONG ProcessId, ULONG64 Size, ULONG Protect,
                       BOOLEAN ReserveOnly, ULONG_PTR *BaseAddress) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  MEMORY_ALLOC_INPUT Input = {};
  Input.ProcessId = ProcessId;
  Input.Operation = MEMREGION_OP_ALLOC;
  Input.Protect = Protect;
  Input.AllocationType = ReserveOnly ? 1u : 0u;
  Input.Size = Size;
  MEMORY_ALLOC_OUTPUT Output = {};
  DWORD BytesReturned = 0;
  const BOOL Success =
      SendIoctlWithOutput(IOCTL_MEMORY_ALLOC_FREE, &Input, sizeof(Input),
                          &Output, sizeof(Output), &BytesReturned);
  if (BaseAddress)
    *BaseAddress = Output.BaseAddress;
  return Success;
}

inline BOOL KernelFreeMemory(ULONG ProcessId, ULONG_PTR Address) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  MEMORY_ALLOC_INPUT Input = {};
  Input.ProcessId = ProcessId;
  Input.Operation = MEMREGION_OP_FREE;
  Input.Address = Address;
  MEMORY_ALLOC_OUTPUT Output = {};
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_MEMORY_ALLOC_FREE, &Input, sizeof(Input),
                             &Output, sizeof(Output), &BytesReturned);
}

inline BOOLEAN DisableDse(PDSE_CONTROL_OUTPUT Output = NULL) {
  DSE_CONTROL_OUTPUT Result = {};

  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_DISABLE_DSE, NULL, 0, &Result,
                                        sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN RestoreDse(PDSE_CONTROL_OUTPUT Output = NULL) {
  DSE_CONTROL_OUTPUT Result = {};

  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_RESTORE_DSE, NULL, 0, &Result,
                                        sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN QueryDse(PDSE_CONTROL_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_QUERY_DSE, NULL, 0, Output,
                                        sizeof(*Output), &BytesReturned);

  if (Success && Output->Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN EnableDebug() { return SendIoctl(IOCTL_ENABLE_DEBUG, NULL, 0); }

inline BOOLEAN DisableDebug() { return SendIoctl(IOCTL_DISABLE_DEBUG, NULL, 0); }

inline BOOLEAN QueryDebugState(PDEBUG_STATE_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_QUERY_DEBUG_STATE, NULL, 0, Output,
                          sizeof(*Output), &BytesReturned);

  if (Success && Output->Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN DisablePatchGuard(PPG_CONTROL_OUTPUT Output = NULL) {
  PG_CONTROL_OUTPUT Result = {};

  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_DISABLE_PATCHGUARD, NULL, 0, &Result,
                          sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN EnablePatchGuardInterception(PPG_CONTROL_OUTPUT Output = NULL) {
  PG_CONTROL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(
      IOCTL_ENABLE_PATCHGUARD_INTERCEPTION, NULL, 0, &Result,
      sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }
  return Success;
}

inline BOOLEAN ClearPatchGuardKprcbContexts(PPG_CONTROL_OUTPUT Output = NULL) {
  PG_CONTROL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(
      IOCTL_CLEAR_PATCHGUARD_KPRCB, NULL, 0, &Result,
      sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }
  return Success;
}

/* 启用 PPN 路径（第三路径）：把 PG 校验例程所在可执行页置 NX �?Hook #PF�?
   �?DisablePatchGuard 的主/辅路径独立，可单独调用�?*/
inline BOOLEAN EnablePPN(PPG_CONTROL_OUTPUT Output = NULL) {
  PG_CONTROL_OUTPUT Result = {};

  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_ENABLE_PPN, NULL, 0, &Result,
                                        sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

inline BOOLEAN DisablePPN(PPG_CONTROL_OUTPUT Output = NULL) {
  PG_CONTROL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_DISABLE_PPN, NULL, 0, &Result,
                                        sizeof(Result), &BytesReturned);
  if (Output != NULL) *Output = Result;
  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }
  return Success;
}

inline BOOLEAN QueryPatchGuard(PPG_CONTROL_OUTPUT Output) {
  if (Output == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_QUERY_PATCHGUARD, NULL, 0, Output,
                                        sizeof(*Output), &BytesReturned);

  if (Success && Output->Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Output->Status);
    return FALSE;
  }

  return Success;
}

/* 取消 PatchGuard 相关�?DPC：驱动侧枚举所�?DPC 队列并解码，摘除
   DeferredContext 为非规范指针�?DeferredRoutine 落在 ntoskrnl 内的条目�?
   DryRun �?0 时只分类不摘除（用于先摸底确认命中是否合理）�?*/
inline BOOLEAN CancelPatchGuardDpcs(PDPC_CANCEL_OUTPUT Output = NULL,
                             BOOLEAN DryRun = FALSE,
                             ULONG MaxCancel = 0) {
  DPC_CANCEL_INPUT Input = {};
  Input.DryRun = DryRun ? 1u : 0u;
  Input.MaxCancel = MaxCancel;

  DPC_CANCEL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_CANCEL_PATCHGUARD_DPC, &Input, sizeof(Input),
                          &Result, sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

/* 取消 PatchGuard 相关�?APC：遍历所有内核线程的 KernelMode APC 队列�?
   摘除 KernelRoutine == ntoskrnl!KiDispatchCallout �?RundownRoutine == NULL
   的条目。DryRun �?0 时只分类不摘除（用于先摸底确认命中是否合理）�?*/
inline BOOLEAN CancelPatchGuardApcs(PAPC_CANCEL_OUTPUT Output = NULL,
                             BOOLEAN DryRun = FALSE,
                             ULONG MaxCancel = 0,
                             ULONG_PTR TargetApcObject = 0,
                             ULONG TargetThreadId = 0) {
  APC_CANCEL_INPUT Input = {};
  Input.DryRun = DryRun ? 1u : 0u;
  Input.MaxCancel = MaxCancel;
  Input.TargetApcObject = TargetApcObject;
  Input.TargetThreadId = TargetThreadId;

  APC_CANCEL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_CANCEL_PATCHGUARD_APC, &Input, sizeof(Input),
                          &Result, sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

/* 列出所有内核 APC（只读清单，不摘链）。与 CancelPatchGuardApcs 走不同的
   IOCTL（IOCTL_ENUM_APC），结果含普通 APC 条目。 */
inline BOOLEAN EnumerateApcs(PAPC_CANCEL_OUTPUT Output = NULL,
                      ULONG_PTR TargetApcObject = 0,
                      ULONG TargetThreadId = 0) {
  APC_CANCEL_INPUT Input = {};
  Input.DryRun = 1; /* 只读：不摘除 */
  Input.TargetApcObject = TargetApcObject;
  Input.TargetThreadId = TargetThreadId;

  APC_CANCEL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success =
      SendIoctlWithOutput(IOCTL_ENUM_APC, &Input, sizeof(Input), &Result,
                          sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Status != 0) {
    G_LastAegisCoreError = AegisCoreNtStatusToWin32(Result.Status);
    return FALSE;
  }

  return Success;
}

/* 查询 APC 捕获状态（不改变 Enable/Clear）。 */
inline BOOLEAN ApcCaptureQuery(PAPC_CAPTURE_CTL_OUTPUT Output = NULL) {
  APC_CAPTURE_CTL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(
      IOCTL_APC_CAPTURE_CTL, NULL, 0, &Result, sizeof(Result), &BytesReturned);

  if (Output != NULL)
    *Output = Result;
  return Success;
}

/* 设置 APC 捕获：Enable=true 启用 / false 停用；Clear=true 顺带清空缓冲。 */
inline BOOLEAN ApcCaptureCtl(BOOLEAN Enable, BOOLEAN Clear,
                      PAPC_CAPTURE_CTL_OUTPUT Output = NULL) {
  APC_CAPTURE_CTL_INPUT Input = {};
  Input.Enable = Enable ? 1u : 0u;
  Input.Clear = Clear ? 1u : 0u;

  APC_CAPTURE_CTL_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(
      IOCTL_APC_CAPTURE_CTL, &Input, sizeof(Input), &Result, sizeof(Result),
      &BytesReturned);

  if (Output != NULL)
    *Output = Result;
  return Success;
}

/* 读取 APC 捕获环形缓冲到调用方缓冲区（大小由 BufferSize 决定）。
   Drain=true 表示"读并清空"：读取后驱动清空环形缓冲，配合 UI 增量追加。
   Output 指向的缓冲区至少应有 sizeof(APC_CAPTURE_OUTPUT) 大。 */
inline BOOLEAN ApcCaptureRead(PAPC_CAPTURE_OUTPUT Output, DWORD BufferSize,
                       PDWORD BytesReturned = NULL, BOOLEAN Drain = FALSE) {
  if (Output == NULL || BufferSize < sizeof(APC_CAPTURE_OUTPUT)) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  APC_CAPTURE_READ_INPUT Input = {};
  Input.Drain = Drain ? 1u : 0u;
  DWORD LocalReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_APC_CAPTURE_READ, &Input,
                                        sizeof(Input), Output, BufferSize,
                                        &LocalReturned);
  if (BytesReturned != NULL)
    *BytesReturned = LocalReturned;
  return Success;
}

/* 读并清空：用于实时增量刷新。 */
inline BOOLEAN ApcCaptureDrain(PAPC_CAPTURE_OUTPUT Output, DWORD BufferSize,
                        PDWORD BytesReturned = NULL) {
  return ApcCaptureRead(Output, BufferSize, BytesReturned, TRUE);
}

/* 主动注入标记 APC（验证扫描器）。 */
inline BOOLEAN InjectTestApc(PAPC_TEST_OUTPUT Output = NULL, ULONG TargetThreadId = 0,
                      ULONG Count = 1, ULONG StallMicros = 100) {
  APC_TEST_INPUT Input = {};
  Input.TargetThreadId = TargetThreadId;
  Input.Count = Count;
  Input.StallMicros = StallMicros;

  APC_TEST_OUTPUT Result = {};
  DWORD BytesReturned = 0;
  BOOLEAN Success = SendIoctlWithOutput(IOCTL_INJECT_TEST_APC, &Input,
                                        sizeof(Input), &Result, sizeof(Result),
                                        &BytesReturned);

  if (Output != NULL)
    *Output = Result;

  if (Success && Result.Injected == 0) {
    G_LastAegisCoreError = ERROR_NOT_FOUND;
    return FALSE;
  }
  return Success;
}

inline BOOL EnumerateWindowsKernel(_Out_writes_bytes_all_(BufferSize) PVOID Buffer,
                            _In_ ULONG BufferSize,
                            _Out_ PULONG EntriesReturned) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (Buffer == NULL || BufferSize < sizeof(KERNEL_WINDOW_ENUM_OUTPUT) ||
      EntriesReturned == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD BytesReturned = 0;
  BOOL Success = SendIoctlWithOutput(IOCTL_ENUM_WINDOWS, NULL, 0, Buffer,
                                     BufferSize, &BytesReturned);

  if (Success) {
    PKERNEL_WINDOW_ENUM_OUTPUT Out = (PKERNEL_WINDOW_ENUM_OUTPUT)Buffer;
    *EntriesReturned = Out->Count;
  }

  return Success;
}

inline BOOL WindowOperationKernel(ULONG ProcessId, ULONG64 Hwnd, ULONG Operation,
                           _In_opt_ PCWSTR NewTitle, LONG NewX, LONG NewY,
                           LONG NewWidth, LONG NewHeight, ULONG Flags) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  KERNEL_WINDOW_OPERATION_INPUT Input = {};
  Input.ProcessId = ProcessId;
  Input.Hwnd = Hwnd;
  Input.Operation = Operation;
  Input.Flags = Flags;
  Input.NewX = NewX;
  Input.NewY = NewY;
  Input.NewWidth = NewWidth;
  Input.NewHeight = NewHeight;
  if (NewTitle != NULL)
    wcsncpy_s(Input.NewTitle, 256, NewTitle, 255);

  return SendIoctl(IOCTL_WINDOW_OPERATION, &Input, sizeof(Input));
}

FORCEINLINE BOOL WindowKill(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_CLOSE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowHide(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_HIDE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowShow(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SHOW, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowMinimize(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_MINIMIZE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowRestore(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_RESTORE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowMaximize(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_MAXIMIZE, NULL, 0, 0, 0,
                               0, Flags);
}

FORCEINLINE BOOL WindowPing(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_PING, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowEnable(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_ENABLE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowDisable(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_DISABLE, NULL, 0, 0, 0, 0,
                               Flags);
}

FORCEINLINE BOOL WindowSetTitle(ULONG Pid, ULONG64 Hwnd, PCWSTR Title,
                                ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SET_TITLE, Title, 0, 0, 0,
                               0, Flags);
}

FORCEINLINE BOOL WindowSetTopmost(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SET_TOPMOST, NULL, 0, 0, 0,
                               0, Flags);
}

FORCEINLINE BOOL WindowRemoveTopmost(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0) {
  return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_REMOVE_TOPMOST, NULL, 0, 0,
                               0, 0, Flags);
}

/* ---- 命令�?---- */
inline BOOL GetProcessCommandLine(ULONG ProcessId, PWCHAR Buffer, ULONG MaxLen) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (Buffer == NULL || MaxLen < 2) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }
  Buffer[0] = L'\0';

  COMMAND_LINE_INPUT Input = {ProcessId};
  ULONG OutSize = sizeof(COMMAND_LINE_INPUT) + MaxLen;
  PBYTE OutBuf = new BYTE[OutSize];
  RtlZeroMemory(OutBuf, OutSize);

  DWORD BytesReturned = 0;
  BOOL Success =
      SendIoctlWithOutput(IOCTL_GET_COMMAND_LINE, &Input, sizeof(Input), OutBuf,
                          OutSize, &BytesReturned);
  if (Success) {
    ULONG CopyLen =
        (BytesReturned > 0 && BytesReturned <= MaxLen - 2) ? BytesReturned : 0;
    if (CopyLen > 0)
      RtlCopyMemory(Buffer, OutBuf, CopyLen);
  }
  delete[] OutBuf;
  return Success;
}

/* ---- 服务 ---- */
inline BOOL ServiceKernelOp(PCWSTR Name, ULONG Op, ULONG SvcType) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  SERVICE_OPERATION_INPUT Input = {};
  Input.Operation = Op;
  Input.ServiceType = SvcType;
  wcsncpy_s(Input.ServiceName, 128, Name, 127);
  return SendIoctl(IOCTL_SERVICE_OPERATION, &Input, sizeof(Input));
}

FORCEINLINE BOOL ServiceStart(PCWSTR Name, ULONG Type = 1) {
  return ServiceKernelOp(Name, 0, Type);
}
FORCEINLINE BOOL ServiceStop(PCWSTR Name, ULONG Type = 1) {
  return ServiceKernelOp(Name, 1, Type);
}
FORCEINLINE BOOL ServiceDisable(PCWSTR Name) {
  return ServiceKernelOp(Name, 2, 0);
}
FORCEINLINE BOOL ServiceEnable(PCWSTR Name) {
  return ServiceKernelOp(Name, 3, 0);
}
FORCEINLINE BOOL ServiceDelete(PCWSTR Name) {
  return ServiceKernelOp(Name, 4, 0);
}

/* ---- 注册�?---- */
inline BOOL RegistryKernelOp(PCWSTR KeyPath, ULONG Op, PCWSTR ValueName,
                      ULONG ValueType, PVOID ValueData, ULONG ValueSize,
                      PVOID OutBuf, ULONG OutSize, PULONG Returned) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  ULONG InSize = sizeof(REG_OPERATION_INPUT) + ValueSize;
  PBYTE InBuf = new BYTE[InSize];
  RtlZeroMemory(InBuf, InSize);
  PREG_OPERATION_INPUT RegIn = (PREG_OPERATION_INPUT)InBuf;
  RegIn->Operation = Op;
  wcsncpy_s(RegIn->KeyPath, 260, KeyPath, 259);
  if (ValueName)
    wcsncpy_s(RegIn->ValueName, 128, ValueName, 127);
  RegIn->ValueType = ValueType;
  RegIn->ValueDataSize = ValueSize;
  if (ValueData && ValueSize)
    RtlCopyMemory(InBuf + sizeof(REG_OPERATION_INPUT), ValueData, ValueSize);

  DWORD BytesReturned = 0;
  BOOL Success = SendIoctlWithOutput(IOCTL_REG_OPERATION, InBuf, InSize, OutBuf,
                                     OutSize, &BytesReturned);
  if (Returned)
    *Returned = BytesReturned;
  delete[] InBuf;
  return Success;
}

FORCEINLINE BOOL RegEnumSubkeys(PCWSTR KeyPath, PVOID OutBuf, ULONG OutSize,
                                PULONG Returned) {
  return RegistryKernelOp(KeyPath, 0, NULL, 0, NULL, 0, OutBuf, OutSize,
                          Returned);
}
FORCEINLINE BOOL RegDeleteKey(PCWSTR KeyPath) {
  return RegistryKernelOp(KeyPath, 1, NULL, 0, NULL, 0, NULL, 0, NULL);
}
FORCEINLINE BOOL RegSetValueKernel(PCWSTR KeyPath, PCWSTR ValName, ULONG Type,
                                   PVOID Data, ULONG Size) {
  return RegistryKernelOp(KeyPath, 2, ValName, Type, Data, Size, NULL, 0, NULL);
}
FORCEINLINE BOOL RegCreateKeyKernel(PCWSTR KeyPath) {
  return RegistryKernelOp(KeyPath, 3, NULL, 0, NULL, 0, NULL, 0, NULL);
}
FORCEINLINE BOOL RegDeleteValueKernel(PCWSTR KeyPath, PCWSTR ValName) {
  return RegistryKernelOp(KeyPath, 4, ValName, 0, NULL, 0, NULL, 0, NULL);
}

/* ---- 会话 ---- */
inline BOOL SessionKernelOp(ULONG SessionId, ULONG Op, PVOID OutBuf, ULONG OutSize,
                     PULONG Returned) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  SESSION_OPERATION_INPUT Input = {SessionId, Op};
  DWORD BytesReturned = 0;
  BOOL Success =
      SendIoctlWithOutput(IOCTL_SESSION_OPERATION, &Input, sizeof(Input),
                          OutBuf, OutSize, &BytesReturned);
  if (Returned)
    *Returned = BytesReturned;
  return Success;
}

FORCEINLINE BOOL EnumSessions(PVOID OutBuf, ULONG OutSize, PULONG Returned) {
  return SessionKernelOp(0, 0, OutBuf, OutSize, Returned);
}
FORCEINLINE BOOL LogoffSession(ULONG SessionId) {
  return SessionKernelOp(SessionId, 1, NULL, 0, NULL);
}

/* ---- Mitigation ---- */
inline BOOL QueryMitigationKernel(ULONG Pid, PVOID OutBuf, ULONG OutSize,
                           PULONG Returned) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  DWORD BytesReturned = 0;
  BOOL Success =
      SendIoctlWithOutput(IOCTL_MITIGATION_QUERY, &Pid, sizeof(ULONG), OutBuf,
                          OutSize, &BytesReturned);
  if (Returned)
    *Returned = BytesReturned;
  return Success;
}

inline BOOL SetMitigationKernel(ULONG Pid, ULONG PolicyId, ULONG64 Flags) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  MITIGATION_SET_INPUT Input = {Pid, PolicyId, Flags};
  return SendIoctl(IOCTL_MITIGATION_SET, &Input, sizeof(Input));
}

/* ---- 同步对象 ---- */
inline BOOL EnumSyncObjectsKernel(PVOID OutBuf, ULONG OutSize, PULONG Count) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  DWORD BytesReturned = 0;
  BOOL Success = SendIoctlWithOutput(IOCTL_ENUM_SYNC_OBJECTS, NULL, 0, OutBuf,
                                     OutSize, &BytesReturned);
  if (Count)
    *Count = BytesReturned;
  return Success;
}

/* ---- 防火�?---- */
inline BOOL FirewallKernelOpEx(PCWSTR RuleName, ULONG Op, ULONG Action, ULONG Port,
                        ULONG Protocol, ULONG RemoteIpv4,
                        const UCHAR *RemoteIpv6, ULONG DirectionMask,
                        ULONG FamilyMask) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  FIREWALL_OPERATION_INPUT Input = {};
  Input.Operation = Op;
  Input.Action = Action;
  Input.RemotePort = Port;
  Input.Protocol = Protocol;
  Input.RemoteIpv4 = RemoteIpv4;
  if (RemoteIpv6)
    CopyMemory(Input.RemoteIpv6, RemoteIpv6, 16);
  Input.DirectionMask = DirectionMask;
  Input.FamilyMask = FamilyMask;
  wcsncpy_s(Input.RuleName, 128, RuleName ? RuleName : L"", 127);
  return SendIoctl(IOCTL_FIREWALL_OPERATION, &Input, sizeof(Input));
}

inline BOOL FirewallKernelOp(PCWSTR RuleName, ULONG Op, ULONG Action, ULONG Port,
                      ULONG Protocol) {
  return FirewallKernelOpEx(RuleName, Op, Action, Port, Protocol, 0, nullptr, 0, 0);
}

inline BOOL EnumerateFirewallRulesKernel(FIREWALL_RULE_OUTPUT *Output) {
  if (!Output) return FALSE;
  ZeroMemory(Output, sizeof(*Output));
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_ENUM_FIREWALL_RULES, nullptr, 0, Output,
                             sizeof(*Output), &BytesReturned);
}

/* ---- 内核特征码扫�?---- */
inline BOOL KernelPatternScan(PCWSTR TargetModule, PCWSTR PatternText,
                       KERNEL_PATTERN_SCAN_OUTPUT *Output) {
  if (!Output || !PatternText) return FALSE;
  G_LastAegisCoreError = ERROR_SUCCESS;
  KERNEL_PATTERN_SCAN_INPUT Input = {};
  Input.Size = sizeof(Input);
  if (TargetModule)
    wcsncpy_s(Input.TargetModule, TargetModule, 127);
  wcsncpy_s(Input.PatternText, PatternText,
            KERNEL_PATTERN_SCAN_MAX_PATTERN - 1);
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_KERNEL_PATTERN_SCAN, &Input, sizeof(Input),
                             Output, sizeof(*Output), &BytesReturned);
}

/* ---- 可疑内存扫描 ---- */
inline BOOL SuspiciousMemoryScan(ULONG ProcessId, SUSPECT_MEMORY_OUTPUT *Output) {
  if (!Output) return FALSE;
  G_LastAegisCoreError = ERROR_SUCCESS;
  SUSPECT_MEMORY_INPUT Input = {ProcessId, 0};
  DWORD BytesReturned = 0;
  return SendIoctlWithOutput(IOCTL_SUSPICIOUS_MEMORY_SCAN, &Input,
                             sizeof(Input), Output, sizeof(*Output),
                             &BytesReturned);
}

/* ---- 窗口保护 ---- */
inline BOOL ProtectWindowKernel(ULONG Pid, ULONG64 Hwnd, ULONG Flags) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  WINDOW_PROTECT_INPUT Input = {Pid, Hwnd, Flags ? Flags : WINPROT_ALL};
  return SendIoctl(IOCTL_ADD_WINDOW_PROTECT, &Input, sizeof(Input));
}

inline BOOL UnprotectWindowKernel(ULONG Pid, ULONG64 Hwnd) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  WINDOW_PROTECT_INPUT Input = {Pid, Hwnd, 0};
  return SendIoctl(IOCTL_REMOVE_WINDOW_PROTECT, &Input, sizeof(Input));
}

/* ---- 注入防护（非 PPL�?---- */
inline BOOL AddInjectionProtectKernel(ULONG Pid) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  INJECTION_PROTECT_INPUT Input = {Pid};
  return SendIoctl(IOCTL_ADD_INJECTION_PROTECTION, &Input, sizeof(Input));
}

inline BOOL RemoveInjectionProtectKernel(ULONG Pid) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  INJECTION_PROTECT_INPUT Input = {Pid};
  return SendIoctl(IOCTL_REMOVE_INJECTION_PROTECTION, &Input, sizeof(Input));
}

/* ---- 句柄操作 ---- */
inline BOOL ForceCloseHandleKernel(ULONG ProcessId, ULONG HandleValue) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  HANDLE_CLOSE_INPUT Input = {ProcessId, HandleValue};
  return SendIoctl(IOCTL_HANDLE_CLOSE, &Input, sizeof(Input));
}

inline BOOL DowngradeHandleKernel(ULONG ProcessId, ULONG HandleValue,
                           ACCESS_MASK NewAccess, ULONG *OutNewHandle) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (OutNewHandle)
    *OutNewHandle = 0;

  HANDLE_DOWNGRADE_INPUT Input = {ProcessId, HandleValue, NewAccess, 0};
  // IOCTL_HANDLE_DOWNGRADE 为 METHOD_BUFFERED：输入输出共用 SystemBuffer，
  // 驱动把新句柄写回 Input.NewHandleValue。必须用 SendIoctlWithOutput 并以
  // Input 作为输出缓冲，否则读不回新句柄（此前用 SendIoctl 恒为 0）。
  if (!SendIoctlWithOutput(IOCTL_HANDLE_DOWNGRADE, &Input, sizeof(Input), &Input,
                           sizeof(Input), nullptr))
    return FALSE;

  if (OutNewHandle)
    *OutNewHandle = Input.NewHandleValue;

  return TRUE;
}

inline BOOL DuplicateAndDowngradeHandleKernel(ULONG SourcePid, ULONG SourceHandle,
                                       ULONG TargetPid, ACCESS_MASK NewAccess,
                                       ULONG_PTR *OutNewHandle) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (OutNewHandle)
    *OutNewHandle = 0;

  HANDLE_DUP_DOWNGRADE_INPUT Input = {SourcePid, SourceHandle, TargetPid,
                                      NewAccess};
  HANDLE_DUP_DOWNGRADE_OUTPUT Output = {0};

  if (!SendIoctlWithOutput(IOCTL_HANDLE_DUP_DOWNGRADE, &Input, sizeof(Input),
                           &Output, sizeof(Output), nullptr)) {
    return FALSE;
  }

  if (OutNewHandle)
    *OutNewHandle = Output.NewHandle;

  G_LastAegisCoreError = Output.Status;
  return NT_SUCCESS(Output.Status);
}

inline BOOLEAN SetIdtLimit() {
  BOOLEAN Success = SendIoctl(IOCTL_SET_IDT_LIMIT, 0, 0);

  return Success;
}

/* ---- 线程劫持操作 ---- */

inline BOOLEAN HijackThreadContext(ULONG ThreadId, ULONG_PTR TargetRip) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (ThreadId == 0 || TargetRip == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  THREAD_HIJACK_INPUT Input = {ThreadId, TargetRip};
  return SendIoctl(IOCTL_THREAD_HIJACK_CONTEXT, &Input, sizeof(Input));
}

inline BOOLEAN HijackThreadTrapFrame(ULONG ThreadId, ULONG_PTR TargetRip) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (ThreadId == 0 || TargetRip == 0) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  THREAD_HIJACK_INPUT Input = {ThreadId, TargetRip};
  return SendIoctl(IOCTL_THREAD_HIJACK_TRAPFRAME, &Input, sizeof(Input));
}

inline BOOLEAN RemoteCallViaKernel(ULONG ThreadId, ULONG_PTR Function,
                            ULONG_PTR Arg1, ULONG_PTR Arg2,
                            ULONG_PTR Arg3, ULONG_PTR Arg4,
                            PLONG OutResult) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (ThreadId == 0 || Function == 0 || OutResult == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  THREAD_REMOTE_CALL_INPUT  Input  = {ThreadId, Function, {Arg1, Arg2, Arg3, Arg4}};
  THREAD_REMOTE_CALL_OUTPUT Output = {0};

  DWORD BytesReturned = 0;
  if (!SendIoctlWithOutput(IOCTL_THREAD_REMOTE_CALL, &Input, sizeof(Input),
                           &Output, sizeof(Output), &BytesReturned)) {
    return FALSE;
  }

  *OutResult = Output.Result;
  return TRUE;
}

/* ---- Shellcode 注入 + 线程劫持 ---- */

inline BOOLEAN InjectShellcode(ULONG ProcessId, const UCHAR *Shellcode, ULONG Size,
                        ULONG_PTR *OutAddress) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (ProcessId == 0 || Shellcode == NULL || Size == 0 || OutAddress == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD TotalSize = sizeof(SHELLCODE_INJECT_INPUT) + Size;
  PUCHAR Buffer = (PUCHAR)malloc(TotalSize);
  if (Buffer == NULL) {
    G_LastAegisCoreError = ERROR_OUTOFMEMORY;
    return FALSE;
  }

  PSHELLCODE_INJECT_INPUT Header = (PSHELLCODE_INJECT_INPUT)Buffer;
  Header->Id   = ProcessId;
  Header->Size = Size;
  memcpy(Buffer + sizeof(SHELLCODE_INJECT_INPUT), Shellcode, Size);

  SHELLCODE_INJECT_OUTPUT Output = {0};
  DWORD BytesReturned = 0;
  BOOLEAN Ok = SendIoctlWithOutput(IOCTL_THREAD_SHELLCODE_INJECT, Buffer,
                                   TotalSize, &Output, sizeof(Output),
                                   &BytesReturned);
  free(Buffer);
  *OutAddress = Output.AllocatedAddress;
  return Ok;
}

inline BOOLEAN InjectAndHijack(ULONG ThreadId, const UCHAR *Shellcode, ULONG Size,
                        ULONG_PTR *OutAddress) {
  G_LastAegisCoreError = ERROR_SUCCESS;
  if (ThreadId == 0 || Shellcode == NULL || Size == 0 || OutAddress == NULL) {
    G_LastAegisCoreError = ERROR_INVALID_PARAMETER;
    return FALSE;
  }

  DWORD TotalSize = sizeof(SHELLCODE_INJECT_INPUT) + Size;
  PUCHAR Buffer = (PUCHAR)malloc(TotalSize);
  if (Buffer == NULL) {
    G_LastAegisCoreError = ERROR_OUTOFMEMORY;
    return FALSE;
  }

  PSHELLCODE_INJECT_INPUT Header = (PSHELLCODE_INJECT_INPUT)Buffer;
  Header->Id   = ThreadId;
  Header->Size = Size;
  memcpy(Buffer + sizeof(SHELLCODE_INJECT_INPUT), Shellcode, Size);

  SHELLCODE_INJECT_OUTPUT Output = {0};
  DWORD BytesReturned = 0;
  BOOLEAN Ok = SendIoctlWithOutput(IOCTL_THREAD_INJECT_AND_HIJACK, Buffer,
                                   TotalSize, &Output, sizeof(Output),
                                   &BytesReturned);
  free(Buffer);
  *OutAddress = Output.AllocatedAddress;
  return Ok;
}
