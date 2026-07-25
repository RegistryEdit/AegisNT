#pragma once
#include <windows.h>
#include <winioctl.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

#define IOCTL_KILL_PROCESS            CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROCESS_PROTECT     CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PROCESS_PROTECT  CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_REGISTRY_PROTECT    CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_REGISTRY_PROTECT CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_FILE_PROTECT        CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_FILE_PROTECT     CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PPL                 CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PPL              CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_ALL_PROTECTION    CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_OBCALLBACKS        CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_REGISTRYCALLBACKS  CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_ALL_FILTERS            CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS             CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_CALLBACK_BY_ADDRESS CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PPL                CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_CRITICAL            CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_CRITICAL         CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS            CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_PROCESS          CTL_CODE(0x8000, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FORCE_DELETE_FILE       CTL_CODE(0x8000, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADJUST_PRIVILEGES       CTL_CODE(0x8000, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUEUE_APC               CTL_CODE(0x8000, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PROCESSES          CTL_CODE(0x8000, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_APC             CTL_CODE(0x8000, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_APC              CTL_CODE(0x8000, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN             CTL_CODE(0x8000, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LAUNCH_AS               CTL_CODE(0x8000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY             CTL_CODE(0x8000, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY            CTL_CODE(0x8000, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_SYSTEM_TABLES     CTL_CODE(0x8000, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_SYSTEM_TABLE_ENTRIES CTL_CODE(0x8000, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_DRIVERS            CTL_CODE(0x8000, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOAD_DRIVER             CTL_CODE(0x8000, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER           CTL_CODE(0x8000, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PIDDB_CACHE        CTL_CODE(0x8000, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PREVIOUS_MODE      CTL_CODE(0x8000, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_CAPABILITIES_V2  CTL_CODE(0x8000, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PROCESS_V2       CTL_CODE(0x8000, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_THREADS_V2        CTL_CODE(0x8000, 0x82E, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_HANDLES_V2        CTL_CODE(0x8000, 0x82F, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MODULES_V2        CTL_CODE(0x8000, 0x830, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MEMORY_V2         CTL_CODE(0x8000, 0x831, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_MEMORY_V2        CTL_CODE(0x8000, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_BIG_POOL_V2       CTL_CODE(0x8000, 0x833, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_OBJECTS_V2        CTL_CODE(0x8000, 0x834, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_KERNEL_MODULES_V2 CTL_CODE(0x8000, 0x835, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_DRIVER_V2        CTL_CODE(0x8000, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_MINIFILTERS_V2    CTL_CODE(0x8000, 0x837, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_WFP_V2            CTL_CODE(0x8000, 0x838, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_ENUM_NDIS_V2           CTL_CODE(0x8000, 0x839, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_QUERY_SECURITY_V2      CTL_CODE(0x8000, 0x83A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TERMINATE_THREAD       CTL_CODE(0x8000, 0x83B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNEL_READ_MEMORY     CTL_CODE(0x8000, 0x83C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNEL_WRITE_MEMORY    CTL_CODE(0x8000, 0x83D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_DSE            CTL_CODE(0x8000, 0x83E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESTORE_DSE            CTL_CODE(0x8000, 0x83F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DLL_INJECT_APC         CTL_CODE(0x8000, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DLL_INJECT_THREAD      CTL_CODE(0x8000, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_DEBUG           CTL_CODE(0x8000, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_DEBUG          CTL_CODE(0x8000, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_DEBUG_STATE      CTL_CODE(0x8000, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_WINDOWS           CTL_CODE(0x8000, 0x845, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDOW_OPERATION       CTL_CODE(0x8000, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_COMMAND_LINE       CTL_CODE(0x8000, 0x847, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SERVICE_OPERATION      CTL_CODE(0x8000, 0x848, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REG_OPERATION          CTL_CODE(0x8000, 0x849, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SESSION_OPERATION      CTL_CODE(0x8000, 0x84A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MITIGATION_QUERY       CTL_CODE(0x8000, 0x84B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MITIGATION_SET         CTL_CODE(0x8000, 0x84C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_SYNC_OBJECTS      CTL_CODE(0x8000, 0x84D, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_FIREWALL_OPERATION     CTL_CODE(0x8000, 0x84E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_WINDOW_PROTECT     CTL_CODE(0x8000, 0x84F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_WINDOW_PROTECT  CTL_CODE(0x8000, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_INJECTION_PROTECTION     CTL_CODE(0x8000, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_INJECTION_PROTECTION  CTL_CODE(0x8000, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CALLBACK_TYPE_OB_PROCESS   0
#define CALLBACK_TYPE_OB_THREAD    1
#define CALLBACK_TYPE_REGISTRY     2
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
#define CALLBACK_FLAG_CAN_REMOVE   0x00000001ul
typedef struct _KILL_PROCESS_INPUT {
	ULONG ProcessId;
} KILL_PROCESS_INPUT;

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
	ULONG  ProcessId;
	UCHAR  ProtectionType;
	UCHAR  ProtectionSigner;
	BOOLEAN Audit;
	BOOLEAN RemoveProtection;
} PPL_CONTROL_INPUT;

typedef struct _CALLBACK_ENTRY {
	ULONG     Type;
	ULONG     Flags;
	ULONG_PTR Address;
	WCHAR     ModuleName[64];
	WCHAR     SourceName[64];
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

typedef struct _CALLBACK_ENUM_OUTPUT {
	ULONG          Count;
	CALLBACK_ENTRY Entries[1];
} CALLBACK_ENUM_OUTPUT, * PCALLBACK_ENUM_OUTPUT;

typedef struct _CALLBACK_REMOVE_INPUT {
	ULONG     Type;
	ULONG     Flags;
	ULONG_PTR Address;
} CALLBACK_REMOVE_INPUT, * PCALLBACK_REMOVE_INPUT;

typedef struct _PPL_QUERY_INPUT {
	ULONG ProcessId;
} PPL_QUERY_INPUT;

typedef struct _PPL_QUERY_OUTPUT {
	ULONG  ProcessId;
	UCHAR  ProtectionType;
	UCHAR  ProtectionSigner;
	BOOLEAN Audit;
	BOOLEAN IsProtected;
	UCHAR  RawLevel;
} PPL_QUERY_OUTPUT;

typedef struct _CRITICAL_PROCESS_INPUT {
	ULONG ProcessId;
} CRITICAL_PROCESS_INPUT;

typedef struct _FORCE_DELETE_INPUT {
	WCHAR FilePath[260];
} FORCE_DELETE_INPUT;

typedef struct _PRIVILEGE_ADJUST_INPUT {
	ULONG   ProcessId;
	LUID    PrivilegeLuid;
	BOOLEAN Enable;
} PRIVILEGE_ADJUST_INPUT;

typedef struct _APC_INPUT {
	ULONG  ProcessId;
	ULONG  ApcAction;
} APC_INPUT;

typedef struct _STEAL_TOKEN_INPUT {
	ULONG SourceProcessId;
	ULONG TargetProcessId;
} STEAL_TOKEN_INPUT;

typedef struct _TERMINATE_THREAD_INPUT {
	ULONG ProcessId;
	ULONG ThreadId;
} TERMINATE_THREAD_INPUT;

#define ACCOUNT_TYPE_SYSTEM           0
#define ACCOUNT_TYPE_TRUSTEDINSTALLER 1

typedef struct _DLL_INJECT_INPUT {
	ULONG  ProcessId;
	WCHAR  DllPath[260];
} DLL_INJECT_INPUT;

typedef struct _LAUNCH_AS_INPUT {
	ULONG  AccountType;
	WCHAR  ImagePath[260];
	ULONG  ProcessId;
	ULONG  ThreadId;
	ULONG  ErrorCode;
} LAUNCH_AS_INPUT;

#define APC_ACTION_NOOP      0
#define APC_ACTION_TERMINATE    1
#define APC_ACTION_EXIT_THREAD  2
#define APC_ACTION_HANG         3

typedef struct _PROCESS_ENUM_ENTRY {
	ULONG   ProcessId;
	ULONG   ParentPid;
	ULONG   ThreadCount;
	ULONG   SessionId;
	BOOLEAN IsPplProtected;
	BOOLEAN IsCritical;
	BOOLEAN IsHidden;
	UCHAR   PplRawLevel;
	UCHAR   _Padding[3];
	WCHAR   ImageName[16];
} PROCESS_ENUM_ENTRY, * PPROCESS_ENUM_ENTRY;

typedef struct _PROCESS_ENUM_OUTPUT {
	ULONG             Count;
	PROCESS_ENUM_ENTRY Entries[1];
} PROCESS_ENUM_OUTPUT, * PPROCESS_ENUM_OUTPUT;

typedef struct _MEMORY_READ_INPUT {
	ULONG     ProcessId;
	ULONG_PTR Address;
	ULONG     Size;
} MEMORY_READ_INPUT, * PMEMORY_READ_INPUT;

typedef struct _MEMORY_WRITE_INPUT {
	ULONG     ProcessId;
	ULONG_PTR Address;
	ULONG     Size;
} MEMORY_WRITE_INPUT, * PMEMORY_WRITE_INPUT;

enum KRNL_MEMRW_METHOD : ULONG {
	KrnlMemRwAuto   = 0,
	KrnlMemRwMdl    = 1,
	KrnlMemRwCr0    = 2,
	KrnlMemRwDirect = 3,
};

typedef struct _KERNEL_READ_INPUT {
	ULONG_PTR        Address;
	ULONG            Size;
	KRNL_MEMRW_METHOD Method;
} KERNEL_READ_INPUT, * PKERNEL_READ_INPUT;

typedef struct _KERNEL_WRITE_INPUT {
	ULONG_PTR        Address;
	ULONG            Size;
	KRNL_MEMRW_METHOD Method;
} KERNEL_WRITE_INPUT, * PKERNEL_WRITE_INPUT;

typedef struct _KERNEL_READ_OUTPUT {
	ULONG BytesRead;
	ULONG Status;
	UCHAR Data[1];
} KERNEL_READ_OUTPUT, * PKERNEL_READ_OUTPUT;

typedef struct _DSE_CONTROL_INPUT {
	ULONG Reserved;
} DSE_CONTROL_INPUT, * PDSE_CONTROL_INPUT;

typedef struct _DSE_CONTROL_OUTPUT {
	ULONG_PTR CiOptionsAddress;
	ULONG     OriginalValue;
	ULONG     CurrentValue;
	ULONG     Status;
} DSE_CONTROL_OUTPUT, * PDSE_CONTROL_OUTPUT;

#define DEBUG_VAR_COUNT 6

typedef struct _DEBUG_VAR_ENTRY {
	ULONG_PTR Address;
	WCHAR     Name[32];
	UCHAR     OriginalValue;
	UCHAR     CurrentValue;
	UCHAR     DesiredEnabledValue;
	BOOLEAN   Found;
	UCHAR     _Pad[4];
} DEBUG_VAR_ENTRY, * PDEBUG_VAR_ENTRY;

static_assert(sizeof(DEBUG_VAR_ENTRY) == 80, "DEBUG_VAR_ENTRY ABI mismatch");

typedef struct _DEBUG_STATE_OUTPUT {
	ULONG           TotalFound;
	ULONG           PatchedSuccessCount;
	BOOLEAN         IsPatched;
	UCHAR           _Pad1[3];
	ULONG           Status;
	DEBUG_VAR_ENTRY Vars[DEBUG_VAR_COUNT];
} DEBUG_STATE_OUTPUT, * PDEBUG_STATE_OUTPUT;

typedef struct _SYSTEM_TABLES_OUTPUT {
	ULONG_PTR IdtBase;
	USHORT    IdtLimit;
	USHORT    _Pad1;

	ULONG_PTR GdtBase;
	USHORT    GdtLimit;
	USHORT    _Pad2;

	ULONG_PTR KuserSharedData;
	ULONG64   InterruptTime;
	ULONG64   SystemTime;
	ULONG     TickCount;
	ULONG     _Pad3;

	ULONG_PTR SsdtBase;
	ULONG     SsdtCount;
	ULONG_PTR SsdtArgTable;

	ULONG_PTR ShadowSsdtBase;
	ULONG     ShadowSsdtCount;
	ULONG_PTR ShadowSsdtArgTable;

	ULONG_PTR PiDDBCacheTable;

	ULONG_PTR NtoskrnlBase;
	ULONG     NtoskrnlSize;
} SYSTEM_TABLES_OUTPUT, * PSYSTEM_TABLES_OUTPUT;

#define SYSTEM_TABLE_KIND_IDT          0
#define SYSTEM_TABLE_KIND_IO_TIMER     1
#define SYSTEM_TABLE_KIND_SSDT         2
#define SYSTEM_TABLE_KIND_SHADOW_SSDT  3
#define SYSTEM_TABLE_KIND_GDT          4
#define SYSTEM_TABLE_MAX_ENTRIES      4096
#define PIDDB_CACHE_MAX_ENTRIES       1024

typedef struct _SYSTEM_TABLE_ENTRY {
	ULONG Index;
	ULONG ArgumentBytes;
	ULONG_PTR Address;
} SYSTEM_TABLE_ENTRY, * PSYSTEM_TABLE_ENTRY;

typedef struct _SYSTEM_TABLE_ENTRIES_OUTPUT {
	ULONG TableKind;
	ULONG Count;
	ULONG TotalCount;
	ULONG_PTR TableBase;
	SYSTEM_TABLE_ENTRY Entries[SYSTEM_TABLE_MAX_ENTRIES];
} SYSTEM_TABLE_ENTRIES_OUTPUT, * PSYSTEM_TABLE_ENTRIES_OUTPUT;

typedef struct _PIDDB_CACHE_ENTRY_INFO {
	ULONG     Index;
	ULONG     TimeDateStamp;
	LONG      LoadStatus;
	ULONG_PTR Address;
	WCHAR     DriverName[128];
} PIDDB_CACHE_ENTRY_INFO, * PPIDDB_CACHE_ENTRY_INFO;

typedef struct _PIDDB_CACHE_ENUM_OUTPUT {
	ULONG     Count;
	ULONG     TotalCount;
	ULONG_PTR TableAddress;
	PIDDB_CACHE_ENTRY_INFO Entries[PIDDB_CACHE_MAX_ENTRIES];
} PIDDB_CACHE_ENUM_OUTPUT, * PPIDDB_CACHE_ENUM_OUTPUT;

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
} DRIVER_ENUM_ENTRY, * PDRIVER_ENUM_ENTRY;

typedef struct _DRIVER_ENUM_HEADER {
	LONG  NtStatus;
	ULONG Count;
	WCHAR Message[256];
} DRIVER_ENUM_HEADER, * PDRIVER_ENUM_HEADER;

typedef struct _DRIVER_ENUM_OUTPUT {
	DRIVER_ENUM_HEADER Header;
	DRIVER_ENUM_ENTRY  Entries[1];
} DRIVER_ENUM_OUTPUT, * PDRIVER_ENUM_OUTPUT;

typedef struct _DRIVER_CONTROL_INPUT {
	WCHAR   ServiceName[128];
	WCHAR   ImagePath[260];
	BOOLEAN DeleteOnUnload;
	UCHAR   Reserved[3];
} DRIVER_CONTROL_INPUT, * PDRIVER_CONTROL_INPUT;

typedef struct _DRIVER_CONTROL_OUTPUT {
	LONG  NtStatus;
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
} DRIVER_CONTROL_OUTPUT, * PDRIVER_CONTROL_OUTPUT;

#define MDV2_PROTOCOL_VERSION 2u
#define MDV2_MAX_PAGE_RECORDS 256u

enum MDV2_DATA_SOURCE : ULONG {
	Mdv2SourceUnknown = 0, Mdv2SourcePublicApi, Mdv2SourceSystemInformation,
	Mdv2SourceObjectManager, Mdv2SourceRegistry, Mdv2SourceProcessEnvironment,
	Mdv2SourceMemoryMap, Mdv2SourceVersionProfile, Mdv2SourceSignatureScan, Mdv2SourceCrossView
};
enum MDV2_CONFIDENCE : ULONG {
	Mdv2ConfidenceUnavailable = 0, Mdv2ConfidenceLow, Mdv2ConfidenceMedium, Mdv2ConfidenceHigh
};
typedef struct _MDV2_QUERY_INPUT {
	ULONG Size; ULONG Version; ULONG Flags; ULONG ProcessId; ULONG TargetId; ULONG MaxEntries;
	ULONG64 Cursor; WCHAR Name[128]; WCHAR Path[260];
} MDV2_QUERY_INPUT, * PMDV2_QUERY_INPUT;
typedef struct _MDV2_LIST_HEADER {
	ULONG Size; ULONG Version; LONG Status; ULONG Source; ULONG Confidence; ULONG Flags;
	ULONG TotalCount; ULONG ReturnedCount; ULONG RequiredSize; ULONG Reserved; ULONG64 NextCursor;
} MDV2_LIST_HEADER, * PMDV2_LIST_HEADER;
typedef struct _MDV2_RECORD {
	ULONG Size; ULONG Kind; ULONG Flags; ULONG Source; ULONG Confidence; LONG Status;
	ULONG ProcessId; ULONG ThreadId; ULONG64 Address; ULONG64 SizeBytes; ULONG64 Value[8];
	WCHAR Name[128]; WCHAR TypeName[64]; WCHAR Path[260]; WCHAR Detail[256];
} MDV2_RECORD, * PMDV2_RECORD;
typedef struct _MDV2_CAPABILITIES_OUTPUT {
	MDV2_LIST_HEADER Header; ULONG OsMajor; ULONG OsMinor; ULONG OsBuild; ULONG Architecture;
	ULONG64 StableCapabilities; ULONG64 ExperimentalCapabilities;
} MDV2_CAPABILITIES_OUTPUT, * PMDV2_CAPABILITIES_OUTPUT;
typedef struct _MDV2_LIST_OUTPUT {
	MDV2_LIST_HEADER Header; MDV2_RECORD Records[1];
} MDV2_LIST_OUTPUT, * PMDV2_LIST_OUTPUT;

static_assert(sizeof(MDV2_QUERY_INPUT) == 808, "MultiDrv V2 request ABI mismatch");
static_assert(sizeof(MDV2_LIST_HEADER) == 48, "MultiDrv V2 header ABI mismatch");
static_assert(sizeof(MDV2_RECORD) == 1528, "MultiDrv V2 record ABI mismatch");
static_assert(sizeof(MDV2_CAPABILITIES_OUTPUT) == 80, "MultiDrv V2 capabilities ABI mismatch");

#define WINDOW_OP_CLOSE              0
#define WINDOW_OP_HIDE               1
#define WINDOW_OP_SHOW               2
#define WINDOW_OP_SET_TITLE          3
#define WINDOW_OP_MINIMIZE           4
#define WINDOW_OP_RESTORE            5
#define WINDOW_OP_SET_POSITION       6
#define WINDOW_OP_SET_SIZE           7
#define WINDOW_OP_ENABLE             8
#define WINDOW_OP_DISABLE            9
#define WINDOW_OP_SET_TOPMOST        10
#define WINDOW_OP_REMOVE_TOPMOST     11
#define WINDOW_OP_FLASH              12
#define WINDOW_OP_REDRAW             13

#define WINDOW_FLAG_DIRECT           0x00000001
#define WINDOW_FLAG_FORCE            0x00000002

#define WINDOW_FLAG_VISIBLE          (1ul << 0)
#define WINDOW_FLAG_ENABLED          (1ul << 1)
#define WINDOW_FLAG_HUNG             (1ul << 2)
#define WINDOW_FLAG_MINIMIZED        (1ul << 3)
#define WINDOW_FLAG_MAXIMIZED        (1ul << 4)
#define WINDOW_FLAG_TOPMOST          (1ul << 5)
#define WINDOW_FLAG_LAYERED          (1ul << 6)
#define WINDOW_FLAG_TOOLWINDOW       (1ul << 7)
#define WINDOW_FLAG_POPUP            (1ul << 8)
#define WINDOW_FLAG_CHILD            (1ul << 9)
#define WINDOW_FLAG_UNICODE          (1ul << 10)
#define WINDOW_FLAG_MDI              (1ul << 11)
#define WINDOW_FLAG_APPWINDOW        (1ul << 12)
#define WINDOW_FLAG_ACTIVE           (1ul << 13)

typedef struct _KERNEL_WINDOW_ENUM_ENTRY {
	UINT64   Hwnd;
	UINT64   ParentHwnd;
	UINT64   OwnerHwnd;
	UINT64   WndProc;
	ULONG    ProcessId;
	ULONG    ThreadId;
	UINT64   DesktopId;
	UINT64   WinstaId;
	ULONG    Style;
	ULONG    ExStyle;
	ULONG    State;
	ULONG    ShowCmd;
	LONG     Left, Top, Right, Bottom;
	LONG     ClientLeft, ClientTop, ClientRight, ClientBottom;
	UCHAR    Alpha;
	UCHAR    Padding1[3];
	USHORT   ClassAtom;
	USHORT   CbWndExtra;
	ULONG    Flags;
	UINT64   FirstChild;
	UINT64   NextSibling;
	UINT64   MenuHandle;
	UINT64   ThreadInfoId;
	ULONG    MessageCount;
	ULONG    Padding2;
	USHORT   TitleLength;
	USHORT   ClassLength;
} KERNEL_WINDOW_ENUM_ENTRY, * PKERNEL_WINDOW_ENUM_ENTRY;

typedef struct _KERNEL_WINDOW_ENUM_OUTPUT {
	ULONG                  Count;
	KERNEL_WINDOW_ENUM_ENTRY Entries[1];
} KERNEL_WINDOW_ENUM_OUTPUT, * PKERNEL_WINDOW_ENUM_OUTPUT;

typedef struct _KERNEL_WINDOW_OPERATION_INPUT {
	ULONG    ProcessId;
	UINT64   Hwnd;
	ULONG    Operation;
	ULONG    Flags;
	WCHAR    NewTitle[256];
	LONG     NewX;
	LONG     NewY;
	LONG     NewWidth;
	LONG     NewHeight;
} KERNEL_WINDOW_OPERATION_INPUT, * PKERNEL_WINDOW_OPERATION_INPUT;

typedef struct _COMMAND_LINE_INPUT {
	ULONG ProcessId;
} COMMAND_LINE_INPUT, * PCOMMAND_LINE_INPUT;

typedef struct _REG_OPERATION_INPUT {
	ULONG Operation;
	WCHAR KeyPath[260];
	WCHAR ValueName[128];
	ULONG ValueType;
	ULONG ValueDataSize;
} REG_OPERATION_INPUT, * PREG_OPERATION_INPUT;

typedef struct _SERVICE_OPERATION_INPUT {
	ULONG Operation;
	WCHAR ServiceName[128];
	ULONG ServiceType;
} SERVICE_OPERATION_INPUT, * PSERVICE_OPERATION_INPUT;

typedef struct _SESSION_OPERATION_INPUT {
	ULONG SessionId;
	ULONG Operation;
} SESSION_OPERATION_INPUT, * PSESSION_OPERATION_INPUT;

typedef struct _MITIGATION_SET_INPUT {
	ULONG ProcessId;
	ULONG PolicyId;
	ULONG64 Flags;
} MITIGATION_SET_INPUT, * PMITIGATION_SET_INPUT;

typedef struct _FIREWALL_OPERATION_INPUT {
	ULONG Operation;
	WCHAR RuleName[128];
	ULONG Action;
	ULONG RemotePort;
	ULONG Protocol;
} FIREWALL_OPERATION_INPUT, * PFIREWALL_OPERATION_INPUT;

typedef struct _WINDOW_PROTECT_INPUT {
	ULONG    ProcessId;
	ULONG64  Hwnd;
	ULONG    Flags;
} WINDOW_PROTECT_INPUT, * PWINDOW_PROTECT_INPUT;

#define WINPROT_CLOSE    0x00000001
#define WINPROT_HIDE     0x00000002
#define WINPROT_TITLE    0x00000004
#define WINPROT_DISABLE  0x00000008
#define WINPROT_MOVE     0x00000010
#define WINPROT_RESIZE   0x00000020
#define WINPROT_TOPMOST  0x00000040
#define WINPROT_ALL      0xFFFFFFFF

typedef struct _INJECTION_PROTECT_INPUT {
	ULONG ProcessId;
} INJECTION_PROTECT_INPUT, * PINJECTION_PROTECT_INPUT;

HANDLE G_DeviceHandle = INVALID_HANDLE_VALUE;
inline DWORD G_LastMultiDrvError = ERROR_SUCCESS;
inline std::wstring G_LastMultiDrvDetails;

BOOLEAN EnsureTrustedInstallerRunning(PULONG OutPid = NULL)
{
	if (OutPid) *OutPid = 0;

	SC_HANDLE Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!Scm)
	{
		G_LastMultiDrvError = GetLastError();
		return FALSE;
	}

	SC_HANDLE Service = OpenServiceW(Scm, L"TrustedInstaller",
		SERVICE_QUERY_STATUS | SERVICE_START);
	if (!Service)
	{
		G_LastMultiDrvError = GetLastError();
		CloseServiceHandle(Scm);
		return FALSE;
	}

	SERVICE_STATUS_PROCESS Status{};
	DWORD BytesNeeded = 0;
	if (!QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&Status), sizeof(Status), &BytesNeeded))
	{
		G_LastMultiDrvError = GetLastError();
		CloseServiceHandle(Service);
		CloseServiceHandle(Scm);
		return FALSE;
	}

	if (Status.dwCurrentState != SERVICE_RUNNING)
	{
		if (!StartServiceW(Service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		{
			G_LastMultiDrvError = GetLastError();
			CloseServiceHandle(Service);
			CloseServiceHandle(Scm);
			return FALSE;
		}

		for (int Attempt = 0; Attempt < 50; ++Attempt)
		{
			Sleep(100);
			if (!QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
				reinterpret_cast<LPBYTE>(&Status), sizeof(Status), &BytesNeeded))
				break;
			if (Status.dwCurrentState == SERVICE_RUNNING && Status.dwProcessId != 0)
			{
				if (OutPid) *OutPid = Status.dwProcessId;
				CloseServiceHandle(Service);
				CloseServiceHandle(Scm);
				return TRUE;
			}
			if (Status.dwCurrentState == SERVICE_STOPPED)
				break;
		}

		G_LastMultiDrvError = ERROR_SERVICE_NOT_ACTIVE;
		CloseServiceHandle(Service);
		CloseServiceHandle(Scm);
		return FALSE;
	}

	if (OutPid) *OutPid = Status.dwProcessId;
	CloseServiceHandle(Service);
	CloseServiceHandle(Scm);
	return TRUE;
}

std::mutex G_DeviceMutex;

BOOLEAN TryOpenDevice()
{
	G_DeviceHandle = CreateFileW(
		L"\\\\.\\MultiDrv",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	return G_DeviceHandle != INVALID_HANDLE_VALUE;
}

BOOLEAN ShouldRetryOpenDeviceError(DWORD Error)
{
	switch (Error)
	{
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_GEN_FAILURE:
	case ERROR_DEVICE_NOT_CONNECTED:
	case ERROR_NOT_READY:
		return TRUE;
	default:
		return FALSE;
	}
}

BOOLEAN OpenDeviceInternal(BOOLEAN Silent)
{
	DWORD LastError = ERROR_FILE_NOT_FOUND;
	for (int Attempt = 0; Attempt < 30; ++Attempt)
	{
		if (TryOpenDevice())
			return TRUE;

		LastError = GetLastError();
		if (!ShouldRetryOpenDeviceError(LastError))
			break;
		Sleep(50);
	}

	SetLastError(LastError);
	if (!Silent)
	{
		wprintf(L"[!] Failed to open \\\\.\\MultiDrv (error %u).\n", LastError);
		wprintf(L"    Is the driver loaded? Run: sc start MultiDrv\n");
	}
	return FALSE;
}

BOOLEAN OpenDevice()
{
	return OpenDeviceInternal(FALSE);
}


BOOLEAN OpenDeviceSilent()
{
	return OpenDeviceInternal(TRUE);
}

VOID CloseDevice()
{
	if (G_DeviceHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(G_DeviceHandle);
		G_DeviceHandle = INVALID_HANDLE_VALUE;
	}
}

BOOLEAN SendIoctl(DWORD IoControlCode, PVOID InputBuffer, DWORD InputSize)
{
    G_LastMultiDrvError = ERROR_SUCCESS;
    std::lock_guard<std::mutex> Lock(G_DeviceMutex);
    if (!OpenDevice())
    {
        G_LastMultiDrvError = GetLastError();
        return FALSE;
	}

	DWORD BytesReturned = 0;
	BOOL  Result = DeviceIoControl(
		G_DeviceHandle,
		IoControlCode,
		InputBuffer,
		InputSize,
		NULL,
		0,
		&BytesReturned,
		NULL);

	if (!Result)
	{
		G_LastMultiDrvError = GetLastError();
		wprintf(L"[!] DeviceIoControl failed: error %u\n", G_LastMultiDrvError);
		CloseDevice();
		return FALSE;
	}

	CloseDevice();
	return TRUE;
}

BOOLEAN SendIoctlWithOutput(DWORD IoControlCode, PVOID InputBuffer, DWORD InputSize,
	PVOID OutputBuffer, DWORD OutputSize, PDWORD BytesReturned)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	std::lock_guard<std::mutex> Lock(G_DeviceMutex);
	if (!OpenDevice())
	{
		G_LastMultiDrvError = GetLastError();
		return FALSE;
	}

	BOOL Result = DeviceIoControl(
		G_DeviceHandle,
		IoControlCode,
		InputBuffer,
		InputSize,
		OutputBuffer,
		OutputSize,
		BytesReturned,
		NULL);

	if (!Result)
	{
		G_LastMultiDrvError = GetLastError();
		wprintf(L"[!] DeviceIoControl failed: error %u\n", G_LastMultiDrvError);
		CloseDevice();
		return FALSE;
	}

	CloseDevice();
	return TRUE;
}

BOOLEAN EnumProcessEntries(std::vector<PROCESS_ENUM_ENTRY>& Entries)
{
	Entries.clear();

	for (int Attempt = 0; Attempt < 2; ++Attempt)
	{
		DWORD BytesReturned = 0;
		DWORD ProbeCount = 0;
		if (!SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0, &ProbeCount, sizeof(ProbeCount), &BytesReturned))
		{
			return FALSE;
		}

		if (ProbeCount == 0)
		{
			return TRUE;
		}

		DWORD BufSz = sizeof(PROCESS_ENUM_OUTPUT) + (ProbeCount - 1) * sizeof(PROCESS_ENUM_ENTRY);
		PROCESS_ENUM_OUTPUT* Out = (PROCESS_ENUM_OUTPUT*)malloc(BufSz);
		if (Out == NULL)
		{
			wprintf(L"[!] Memory allocation failed.\n");
			return FALSE;
		}
		ZeroMemory(Out, BufSz);

		if (SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0, Out, BufSz, &BytesReturned) &&
			Out->Count <= ProbeCount)
		{
			Entries.assign(Out->Entries, Out->Entries + Out->Count);
			free(Out);
			return TRUE;
		}

		free(Out);
	}

	return FALSE;
}

VOID KillProcess(ULONG ProcessId)
{
	wprintf(L"[*] Killing process PID=%u ...\n", ProcessId);

	KILL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_KILL_PROCESS, &Input, sizeof(Input)))
		wprintf(L"[+] Process termination request sent.\n");
}

VOID ProtectProcess(ULONG ProcessId)
{
	wprintf(L"[*] Adding process PID=%u to protection list ...\n", ProcessId);

	PROCESS_PROTECT_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_ADD_PROCESS_PROTECT, &Input, sizeof(Input)))
		wprintf(L"[+] Process PID=%u protected.\n", ProcessId);
}

VOID UnprotectProcess(ULONG ProcessId)
{
	wprintf(L"[*] Removing process PID=%u from protection list ...\n", ProcessId);

	PROCESS_PROTECT_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_REMOVE_PROCESS_PROTECT, &Input, sizeof(Input)))
		wprintf(L"[+] Process PID=%u unprotected.\n", ProcessId);
}

VOID ProtectRegistryKey(const WCHAR* KeyPath)
{
	wprintf(L"[*] Adding registry key to protection: %s\n", KeyPath);

	REGISTRY_PROTECT_INPUT Input = { 0 };
	wcsncpy_s(Input.KeyPath, 256, KeyPath, _TRUNCATE);

	if (SendIoctl(IOCTL_ADD_REGISTRY_PROTECT, &Input, sizeof(Input)))
		wprintf(L"[+] Registry key protected.\n");
}

VOID UnprotectRegistryKey(const WCHAR* KeyPath)
{
	wprintf(L"[*] Removing registry key from protection: %s\n", KeyPath);

	REGISTRY_PROTECT_INPUT Input = { 0 };
	wcsncpy_s(Input.KeyPath, 256, KeyPath, _TRUNCATE);

	if (SendIoctl(IOCTL_REMOVE_REGISTRY_PROTECT, &Input, sizeof(Input)))
		wprintf(L"[+] Registry key unprotected.\n");
}

BOOLEAN ProtectFile(const WCHAR* FilePath)
{
	wprintf(L"[*] Adding file to protection: %s\n", FilePath);

	FILE_PROTECT_INPUT Input = { 0 };
	wcsncpy_s(Input.FilePath, 260, FilePath, _TRUNCATE);

	const BOOLEAN Success = SendIoctl(IOCTL_ADD_FILE_PROTECT, &Input, sizeof(Input));
	if (Success)
		wprintf(L"[+] File protected.\n");
	return Success;
}

BOOLEAN UnprotectFile(const WCHAR* FilePath)
{
	wprintf(L"[*] Removing file from protection: %s\n", FilePath);

	FILE_PROTECT_INPUT Input = { 0 };
	wcsncpy_s(Input.FilePath, 260, FilePath, _TRUNCATE);

	const BOOLEAN Success = SendIoctl(IOCTL_REMOVE_FILE_PROTECT, &Input, sizeof(Input));
	if (Success)
		wprintf(L"[+] File unprotected.\n");
	return Success;
}

VOID SetPpl(ULONG ProcessId, UCHAR ProtectionType, UCHAR ProtectionSigner, BOOLEAN Audit)
{
	wprintf(L"[*] Setting PPL on PID=%u Type=%u Signer=%u Audit=%u ...\n",
		ProcessId, ProtectionType, ProtectionSigner, Audit);

	PPL_CONTROL_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	Input.ProtectionType = ProtectionType;
	Input.ProtectionSigner = ProtectionSigner;
	Input.Audit = Audit;
	Input.RemoveProtection = FALSE;

	if (SendIoctl(IOCTL_SET_PPL, &Input, sizeof(Input)))
		wprintf(L"[+] PPL set on PID=%u.\n", ProcessId);
}

VOID RemovePpl(ULONG ProcessId)
{
	wprintf(L"[*] Removing PPL from PID=%u ...\n", ProcessId);

	PPL_CONTROL_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	Input.RemoveProtection = TRUE;

	if (SendIoctl(IOCTL_REMOVE_PPL, &Input, sizeof(Input)))
		wprintf(L"[+] PPL removed from PID=%u.\n", ProcessId);
}

VOID QueryPpl(ULONG ProcessId)
{
	wprintf(L"[*] Querying PPL for PID=%u ...\n", ProcessId);

	PPL_QUERY_INPUT  Input = { 0 };
	PPL_QUERY_OUTPUT Output = { 0 };
	DWORD BytesReturned = 0;
	Input.ProcessId = ProcessId;

	if (!SendIoctlWithOutput(IOCTL_QUERY_PPL, &Input, sizeof(Input),
		&Output, sizeof(Output), &BytesReturned))
		return;

	wprintf(L"    ProcessId:      %u\n", Output.ProcessId);
	wprintf(L"    IsProtected:    %s\n", Output.IsProtected ? L"Yes" : L"No");

	if (Output.IsProtected)
	{
		wprintf(L"    ProtectionType: ");
		switch (Output.ProtectionType)
		{
		case 0: wprintf(L"None");           break;
		case 1: wprintf(L"ProtectedLight");  break;
		case 2: wprintf(L"Protected");       break;
		default: wprintf(L"Unknown(%u)", Output.ProtectionType); break;
		}
		wprintf(L" (%u)\n", Output.ProtectionType);

		wprintf(L"    ProtectionSigner: ");
		switch (Output.ProtectionSigner)
		{
		case 0: wprintf(L"None");          break;
		case 1: wprintf(L"Authenticode");  break;
		case 2: wprintf(L"CodeGen");       break;
		case 3: wprintf(L"Antimalware");   break;
		case 4: wprintf(L"Lsa");           break;
		case 5: wprintf(L"Windows");       break;
		case 6: wprintf(L"WinTcb");        break;
		case 7: wprintf(L"WinSystem");     break;
		case 8: wprintf(L"App");           break;
		default: wprintf(L"Unknown(%u)", Output.ProtectionSigner); break;
		}
		wprintf(L" (%u)\n", Output.ProtectionSigner);

		wprintf(L"    Audit:          %s\n", Output.Audit ? L"On" : L"Off");
		wprintf(L"    Raw Level:      0x%02X\n", Output.RawLevel);
	}
}

VOID SetCritical(ULONG ProcessId)
{
	wprintf(L"[*] Setting PID=%u as critical process (terminate = BSOD) ...\n", ProcessId);
	wprintf(L"[!] WARNING: Killing this process will crash the system!\n");

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_SET_CRITICAL, &Input, sizeof(Input)))
		wprintf(L"[+] PID=%u is now a critical process.\n", ProcessId);
}

VOID RemoveCritical(ULONG ProcessId)
{
	wprintf(L"[*] Removing critical process flag from PID=%u ...\n", ProcessId);

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_REMOVE_CRITICAL, &Input, sizeof(Input)))
		wprintf(L"[+] PID=%u is no longer a critical process.\n", ProcessId);
}

VOID HideProcess(ULONG ProcessId)
{
	wprintf(L"[*] Hiding PID=%u from task manager ...\n", ProcessId);

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_HIDE_PROCESS, &Input, sizeof(Input)))
		wprintf(L"[+] PID=%u is now hidden.\n", ProcessId);
}

VOID UnhideProcess(ULONG ProcessId)
{
	wprintf(L"[*] Unhiding PID=%u ...\n", ProcessId);

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_UNHIDE_PROCESS, &Input, sizeof(Input)))
		wprintf(L"[+] PID=%u is now visible.\n", ProcessId);
}

BOOLEAN ForceDeleteFile(const WCHAR* FilePath)
{
	if (FilePath == NULL || FilePath[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_NAME;
		return FALSE;
	}

	std::wstring NtPath(FilePath);
	for (wchar_t& Character : NtPath)
		if (Character == L'/') Character = L'\\';

	if (NtPath.rfind(L"\\??\\", 0) != 0 && NtPath.rfind(L"\\Device\\", 0) != 0)
	{
		if (NtPath.rfind(L"\\\\?\\", 0) == 0)
			NtPath = L"\\??\\" + NtPath.substr(4);
		else if (NtPath.rfind(L"\\\\", 0) == 0)
			NtPath = L"\\??\\UNC\\" + NtPath.substr(2);
		else if (NtPath.size() >= 2 && NtPath[1] == L':')
			NtPath = L"\\??\\" + NtPath;
		else
		{
			G_LastMultiDrvError = ERROR_INVALID_NAME;
			return FALSE;
		}
	}

	FORCE_DELETE_INPUT Input = { 0 };
	if (NtPath.size() >= _countof(Input.FilePath))
	{
		G_LastMultiDrvError = ERROR_FILENAME_EXCED_RANGE;
		return FALSE;
	}

	wprintf(L"[*] Force deleting: %ls\n", NtPath.c_str());
	wcscpy_s(Input.FilePath, _countof(Input.FilePath), NtPath.c_str());

	const BOOLEAN Success = SendIoctl(IOCTL_FORCE_DELETE_FILE, &Input, sizeof(Input));
	if (Success)
		wprintf(L"[+] File marked for deletion.\n");
	return Success;
}

VOID AdjustPrivileges(ULONG ProcessId, const WCHAR* PrivName, BOOLEAN Enable)
{
	wprintf(L"[*] %s privilege '%s' on PID=%u ...\n",
		Enable ? L"Enabling" : L"Disabling", PrivName, ProcessId);

	LUID Luid;
	if (!LookupPrivilegeValueW(NULL, PrivName, &Luid))
	{
		wprintf(L"[!] Unknown privilege name: %s (error %u)\n", PrivName, GetLastError());
		return;
	}

	PRIVILEGE_ADJUST_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	Input.PrivilegeLuid = Luid;
	Input.Enable = Enable;

	if (SendIoctl(IOCTL_ADJUST_PRIVILEGES, &Input, sizeof(Input)))
		wprintf(L"[+] Privilege adjusted.\n");
}

VOID QueueApc(ULONG ProcessId, ULONG Action)
{
	wprintf(L"[*] Queuing APC to PID=%u (action=%u) ...\n", ProcessId, Action);

	APC_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	Input.ApcAction = Action;

	if (SendIoctl(IOCTL_QUEUE_APC, &Input, sizeof(Input)))
		wprintf(L"[+] APC queued to PID=%u.\n", ProcessId);
}

VOID DisableApc(ULONG ProcessId)
{
	wprintf(L"[*] Disabling APC delivery for PID=%u ...\n", ProcessId);

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_DISABLE_APC, &Input, sizeof(Input)))
		wprintf(L"[+] APCs disabled for PID=%u.\n", ProcessId);
}

VOID EnableApc(ULONG ProcessId)
{
	wprintf(L"[*] Enabling APC delivery for PID=%u ...\n", ProcessId);

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;

	if (SendIoctl(IOCTL_ENABLE_APC, &Input, sizeof(Input)))
		wprintf(L"[+] APCs re-enabled for PID=%u.\n", ProcessId);
}

BOOLEAN KillThread(ULONG ThreadId, ULONG ProcessId)
{
	wprintf(L"[*] Terminating TID=%u in PID=%u via MultiDrv ...\n", ThreadId, ProcessId);

	TERMINATE_THREAD_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	Input.ThreadId = ThreadId;

	if (!SendIoctl(IOCTL_TERMINATE_THREAD, &Input, sizeof(Input)))
		return FALSE;

	for (int Attempt = 0; Attempt < 20; ++Attempt)
	{
		HANDLE Thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
		if (Thread == NULL)
		{
			G_LastMultiDrvError = ERROR_SUCCESS;
			wprintf(L"[+] TID=%u terminated.\n", ThreadId);
			return TRUE;
		}

		DWORD ExitCode = STILL_ACTIVE;
		const BOOL ExitCodeOk = GetExitCodeThread(Thread, &ExitCode);
		CloseHandle(Thread);
		if (ExitCodeOk && ExitCode != STILL_ACTIVE)
		{
			G_LastMultiDrvError = ERROR_SUCCESS;
			wprintf(L"[+] TID=%u terminated (exit code %u).\n", ThreadId, ExitCode);
			return TRUE;
		}

		Sleep(25);
	}

	G_LastMultiDrvError = WAIT_TIMEOUT;
	wprintf(L"[!] TID=%u did not terminate within the verification window.\n", ThreadId);
	return FALSE;
}

BOOLEAN DllInjectApc(ULONG ProcessId, const WCHAR* DllPath)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	if (DllPath == NULL || DllPath[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DLL_INJECT_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	wcsncpy_s(Input.DllPath, 260, DllPath, _TRUNCATE);

	const BOOLEAN Success = SendIoctl(IOCTL_DLL_INJECT_APC, &Input, sizeof(Input));
	if (Success)
		wprintf(L"[+] APC DLL injection queued to PID=%u: %s\n", ProcessId, DllPath);
	return Success;
}

BOOLEAN DllInjectThread(ULONG ProcessId, const WCHAR* DllPath)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	if (DllPath == NULL || DllPath[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DLL_INJECT_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	wcsncpy_s(Input.DllPath, 260, DllPath, _TRUNCATE);

	const BOOLEAN Success = SendIoctl(IOCTL_DLL_INJECT_THREAD, &Input, sizeof(Input));
	if (Success)
		wprintf(L"[+] Remote thread DLL injection launched in PID=%u: %s\n", ProcessId, DllPath);
	return Success;
}

VOID EnumProcesses()
{
	wprintf(L"[*] Enumerating all processes ...\n\n");

	DWORD BytesReturned = 0;
	ULONG Count = 0;

	if (!SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0,
		&Count, sizeof(Count), &BytesReturned))
	{
		wprintf(L"[!] Failed to query process count.\n");
		return;
	}

	if (Count == 0)
		return;

	wprintf(L"[*] %u process(es) found.\n\n", Count);

	DWORD BufSz = sizeof(PROCESS_ENUM_OUTPUT) + (Count - 1) * sizeof(PROCESS_ENUM_ENTRY);
	PPROCESS_ENUM_OUTPUT Out = (PPROCESS_ENUM_OUTPUT)malloc(BufSz);
	if (Out == NULL)
	{
		wprintf(L"[!] Memory allocation failed.\n");
		return;
	}
	ZeroMemory(Out, BufSz);

	if (!SendIoctlWithOutput(IOCTL_ENUM_PROCESSES, NULL, 0, Out, BufSz, &BytesReturned))
	{
		wprintf(L"[!] Failed to enumerate processes.\n");
		free(Out);
		return;
	}

	wprintf(L"  %-6s  %-15s  %-6s  %5s  %s\n",
		L"PID", L"Name", L"Thrds", L"PPL", L"Flags");
	wprintf(L"  %-6s  %-15s  %-6s  %5s  %s\n",
		L"------", L"---------------", L"------", L"-----", L"-----");

	for (ULONG i = 0; i < Out->Count; i++)
	{
		PPROCESS_ENUM_ENTRY E = &Out->Entries[i];

		WCHAR Flags[32] = { 0 };
		ULONG fp = 0;
		if (E->IsCritical) { Flags[fp++] = 'C'; Flags[fp++] = ' '; }
		if (E->IsHidden) { Flags[fp++] = 'H'; Flags[fp++] = ' '; }

		const WCHAR* PplStr = E->IsPplProtected
			? L"*" : L"";
		WCHAR PplBuf[8];
		swprintf_s(PplBuf, 8, L"%s0x%02X", PplStr, E->PplRawLevel);

		wprintf(L"  %-6u  %-15s  %-6u  %5s  %s\n",
			E->ProcessId,
			E->ImageName[0] ? E->ImageName : L"(none)",
			E->ThreadCount,
			PplBuf,
			Flags[0] ? Flags : L"-");
	}

	free(Out);
}

VOID ClearAllProtection()
{
	wprintf(L"[*] Clearing all protection lists ...\n");

	if (SendIoctl(IOCTL_CLEAR_ALL_PROTECTION, NULL, 0))
		wprintf(L"[+] All protection lists cleared.\n");
}

VOID RemoveAllObCallbacks()
{
	wprintf(L"[*] Removing all Ob (Process/Thread) callbacks ...\n");

	if (SendIoctl(IOCTL_REMOVE_ALL_OBCALLBACKS, NULL, 0))
		wprintf(L"[+] All Ob callbacks removed.\n");
}

VOID RemoveAllRegistryCallbacks()
{
	wprintf(L"[*] Removing all registry callbacks ...\n");

	if (SendIoctl(IOCTL_REMOVE_ALL_REGISTRYCALLBACKS, NULL, 0))
		wprintf(L"[+] All registry callbacks removed.\n");
}

VOID RemoveAllFilters()
{
	wprintf(L"[*] Removing all minifilters ...\n");

	if (SendIoctl(IOCTL_REMOVE_ALL_FILTERS, NULL, 0))
		wprintf(L"[+] All minifilters removed.\n");
}

VOID EnumCallbacks()
{
	wprintf(L"[*] Enumerating all registered callbacks ...\n\n");

	DWORD BytesReturned = 0;
	ULONG Count = 0;

	if (!SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, NULL, 0, &Count, sizeof(Count), &BytesReturned))
	{
		wprintf(L"[!] Failed to query callback count.\n");
		return;
	}

	if (Count == 0)
	{
		wprintf(L"[*] No callbacks registered.\n");
		return;
	}

	wprintf(L"[*] Found %u callback(s).\n\n", Count);

	DWORD BufferSize = sizeof(CALLBACK_ENUM_OUTPUT) + (Count - 1) * sizeof(CALLBACK_ENTRY);
	PCALLBACK_ENUM_OUTPUT Out = (PCALLBACK_ENUM_OUTPUT)malloc(BufferSize);
	if (Out == NULL)
	{
		wprintf(L"[!] Memory allocation failed.\n");
		return;
	}
	ZeroMemory(Out, BufferSize);

	if (!SendIoctlWithOutput(IOCTL_ENUM_CALLBACKS, NULL, 0, Out, BufferSize, &BytesReturned))
	{
		wprintf(L"[!] Failed to enumerate callbacks.\n");
		free(Out);
		return;
	}

	wprintf(L"  %-10s %-18s  %-16s  %s\n", L"Type", L"Address", L"Module", L"Source");
	wprintf(L"  %-10s %-18s  %-16s  %s\n", L"----------", L"------------------", L"----------------", L"------");

	for (ULONG i = 0; i < Out->Count; i++)
	{
		PCALLBACK_ENTRY Entry = &Out->Entries[i];
		const WCHAR* TypeStr;

		switch (Entry->Type)
		{
		case CALLBACK_TYPE_OB_PROCESS: TypeStr = L"ObProc";  break;
		case CALLBACK_TYPE_OB_THREAD:  TypeStr = L"ObThread"; break;
		case CALLBACK_TYPE_REGISTRY:   TypeStr = L"Reg";     break;
		case CALLBACK_TYPE_FLT_PRE_CREATE: TypeStr = L"FltCreate"; break;
		case CALLBACK_TYPE_FLT_PRE_SET_INFORMATION: TypeStr = L"FltSetInfo"; break;
		case CALLBACK_TYPE_FLT_PRE_WRITE: TypeStr = L"FltWrite"; break;
		case CALLBACK_TYPE_FLT_PRE_READ: TypeStr = L"FltRead"; break;
		case CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION: TypeStr = L"FltQueryInfo"; break;
		case CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL: TypeStr = L"FltDirCtrl"; break;
		case CALLBACK_TYPE_FLT_PRE_CLEANUP: TypeStr = L"FltCleanup"; break;
		case CALLBACK_TYPE_FLT_PRE_CLOSE: TypeStr = L"FltClose"; break;
		case CALLBACK_TYPE_FLT_POST_CREATE: TypeStr = L"FltPostCreate"; break;
		case CALLBACK_TYPE_FLT_POST_READ: TypeStr = L"FltPostRead"; break;
		case CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION: TypeStr = L"FltPostQuery"; break;
		case CALLBACK_TYPE_FLT_POST_SET_INFORMATION: TypeStr = L"FltPostSet"; break;
		case CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL: TypeStr = L"FltPostDir"; break;
		case CALLBACK_TYPE_FLT_POST_WRITE: TypeStr = L"FltPostWrite"; break;
		case CALLBACK_TYPE_FLT_POST_CLEANUP: TypeStr = L"FltPostCleanup"; break;
		case CALLBACK_TYPE_FLT_POST_CLOSE: TypeStr = L"FltPostClose"; break;
		case CALLBACK_TYPE_PS_PROCESS_NOTIFY: TypeStr = L"PsProcess"; break;
		case CALLBACK_TYPE_PS_THREAD_NOTIFY: TypeStr = L"PsThread"; break;
		case CALLBACK_TYPE_PS_IMAGE_NOTIFY: TypeStr = L"PsImage"; break;
		case CALLBACK_TYPE_BUGCHECK: TypeStr = L"BugCheck"; break;
		case CALLBACK_TYPE_SHUTDOWN: TypeStr = L"Shutdown"; break;
		case CALLBACK_TYPE_BUGCHECK_REASON: TypeStr = L"BugChkReason"; break;
		default:                        TypeStr = L"Unknown"; break;
		}

		wprintf(L"  %-10s 0x%016llX  %-16s  %s\n",
			TypeStr,
			(unsigned long long)Entry->Address,
			Entry->ModuleName[0] ? Entry->ModuleName : L"(unknown)",
			Entry->SourceName[0] ? Entry->SourceName : L"(unknown)");
	}

	wprintf(L"\n[+] Enumeration complete.\n");
	free(Out);
}

VOID RemoveCallbackByAddress(const WCHAR* AddrStr)
{
	ULONG_PTR Address = wcstoull(AddrStr, NULL, 16);
	if (Address == 0)
	{
		wprintf(L"[!] Invalid address: %s\n", AddrStr);
		return;
	}

	wprintf(L"[!] CLI remove by address is no longer safe without a callback type.\n");
	wprintf(L"    Address parsed: 0x%016llX\n", (unsigned long long)Address);
}

static ULONG ResolveAccountPid(ULONG AccountType)
{
	if (AccountType == ACCOUNT_TYPE_SYSTEM)
		return 4;

	if (AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER)
	{
		ULONG Pid = 0;
		if (!EnsureTrustedInstallerRunning(&Pid))
			return 0;
		return Pid;
	}

	return 0;
}

BOOLEAN SetToken(ULONG SourcePid, ULONG TargetPid)
{
	if (SourcePid == 0 || TargetPid == 0)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	STEAL_TOKEN_INPUT Input = { 0 };
	Input.SourceProcessId = SourcePid;
	Input.TargetProcessId = TargetPid;

	return SendIoctl(IOCTL_STEAL_TOKEN, &Input, sizeof(Input));
}

BOOLEAN SetTokenAs(ULONG AccountType, ULONG TargetPid, PULONG OutSourcePid = NULL)
{
	ULONG AccountPid = ResolveAccountPid(AccountType);
	if (AccountPid == 0)
	{
		G_LastMultiDrvError = ERROR_NOT_FOUND;
		return FALSE;
	}

	if (OutSourcePid) *OutSourcePid = AccountPid;
	return SetToken(AccountPid, TargetPid);
}

static BOOLEAN ConvertLaunchPathToWin32Path(const WCHAR* ImagePath, std::wstring& Win32Path)
{
	Win32Path.clear();
	if (ImagePath == NULL || ImagePath[0] == L'\0')
		return FALSE;

	const std::wstring Path(ImagePath);
	if (Path.size() >= 4 && _wcsnicmp(Path.c_str(), L"\\??\\", 4) == 0)
	{
		Win32Path = Path.substr(4);
		return !Win32Path.empty();
	}

	if (Path.size() >= 12 && _wcsnicmp(Path.c_str(), L"\\Device\\Mup\\", 12) == 0)
	{
		Win32Path = L"\\\\";
		Win32Path.append(Path.substr(12));
		return TRUE;
	}

	if (Path.size() >= 12 && _wcsnicmp(Path.c_str(), L"\\SystemRoot\\", 12) == 0)
	{
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
		(Path[2] == L'\\' || Path[2] == L'/'))
	{
		Win32Path = Path;
		return TRUE;
	}

	WCHAR Drives[512] = {};
	const DWORD DriveLength = GetLogicalDriveStringsW(ARRAYSIZE(Drives), Drives);
	if (DriveLength == 0 || DriveLength >= ARRAYSIZE(Drives))
		return FALSE;

	for (const WCHAR* Drive = Drives; *Drive != L'\0'; Drive += wcslen(Drive) + 1)
	{
		if (wcslen(Drive) < 2 || Drive[1] != L':')
			continue;

		WCHAR DeviceName[512] = {};
		WCHAR DriveName[3] = { Drive[0], L':', L'\0' };
		if (QueryDosDeviceW(DriveName, DeviceName, ARRAYSIZE(DeviceName)) == 0)
			continue;

		const size_t PrefixLength = wcslen(DeviceName);
		if (_wcsnicmp(Path.c_str(), DeviceName, PrefixLength) != 0)
			continue;

		if (Path.size() > PrefixLength &&
			Path[PrefixLength] != L'\\' &&
			Path[PrefixLength] != L'/')
			continue;

		Win32Path.assign(DriveName);
		Win32Path.append(Path.substr(PrefixLength));
		return TRUE;
	}

	return FALSE;
}

BOOLEAN LaunchAs(ULONG AccountType, const WCHAR* ImagePath, PULONG OutProcessId = NULL)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	if (OutProcessId) *OutProcessId = 0;
	if (ImagePath == NULL || ImagePath[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (AccountType != ACCOUNT_TYPE_SYSTEM && AccountType != ACCOUNT_TYPE_TRUSTEDINSTALLER)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (AccountType == ACCOUNT_TYPE_TRUSTEDINSTALLER)
	{
		ULONG TrustedInstallerPid = 0;
		if (!EnsureTrustedInstallerRunning(&TrustedInstallerPid) || TrustedInstallerPid == 0)
		{
			G_LastMultiDrvError = ERROR_NOT_FOUND;
			return FALSE;
		}
	}

	std::wstring Win32Path;
	if (!ConvertLaunchPathToWin32Path(ImagePath, Win32Path))
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
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

	const BOOL Created = CreateProcessW(
		Win32Path.c_str(),
		MutableCommandLine.data(),
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL,
		WorkingDirectory.empty() ? NULL : WorkingDirectory.c_str(),
		&StartupInfo,
		&ProcessInfo);
	if (!Created)
	{
		G_LastMultiDrvError = GetLastError();
		return FALSE;
	}

	const DWORD ResumeResult = ResumeThread(ProcessInfo.hThread);
	if (ResumeResult == static_cast<DWORD>(-1))
	{
		G_LastMultiDrvError = GetLastError();
		TerminateProcess(ProcessInfo.hProcess, static_cast<UINT>(G_LastMultiDrvError));
		CloseHandle(ProcessInfo.hThread);
		CloseHandle(ProcessInfo.hProcess);
		return FALSE;
	}

	AllowSetForegroundWindow(ProcessInfo.dwProcessId);
	WaitForInputIdle(ProcessInfo.hProcess, 2000);
	Sleep(250);

	if (!SetTokenAs(AccountType, ProcessInfo.dwProcessId))
	{
		const DWORD TokenError = G_LastMultiDrvError != ERROR_SUCCESS ? G_LastMultiDrvError : ERROR_ACCESS_DENIED;
		TerminateProcess(ProcessInfo.hProcess, static_cast<UINT>(TokenError));
		CloseHandle(ProcessInfo.hThread);
		CloseHandle(ProcessInfo.hProcess);
		G_LastMultiDrvError = TokenError;
		return FALSE;
	}

	if (OutProcessId) *OutProcessId = ProcessInfo.dwProcessId;
	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);
	return TRUE;
}

BOOLEAN ReadMemory(ULONG ProcessId, ULONG_PTR Address, PVOID Buffer, ULONG Size, PULONG BytesRead)
{
	if (BytesRead) *BytesRead = 0;
	if (Buffer == NULL || Size == 0)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD BufSz = sizeof(MEMORY_READ_INPUT) + Size;
	PMEMORY_READ_INPUT Input = (PMEMORY_READ_INPUT)malloc(BufSz);
	if (Input == NULL)
	{
		G_LastMultiDrvError = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}

	ZeroMemory(Input, BufSz);
	Input->ProcessId = ProcessId;
	Input->Address = Address;
	Input->Size = Size;

	DWORD BytesReturned = 0;
	BOOLEAN Success = SendIoctlWithOutput(IOCTL_READ_MEMORY, Input, sizeof(MEMORY_READ_INPUT),
		Input, BufSz, &BytesReturned);

	if (Success && BytesReturned > sizeof(MEMORY_READ_INPUT))
	{
		ULONG ActualRead = BytesReturned - sizeof(MEMORY_READ_INPUT);
		CopyMemory(Buffer, (PUCHAR)Input + sizeof(MEMORY_READ_INPUT), ActualRead);
		if (BytesRead) *BytesRead = ActualRead;
	}

	free(Input);
	return Success;
}

BOOLEAN WriteMemory(ULONG ProcessId, ULONG_PTR Address, PVOID Buffer, ULONG Size)
{
	if (Buffer == NULL || Size == 0)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD BufSz = sizeof(MEMORY_WRITE_INPUT) + Size;
	PMEMORY_WRITE_INPUT Input = (PMEMORY_WRITE_INPUT)malloc(BufSz);
	if (Input == NULL)
	{
		G_LastMultiDrvError = ERROR_NOT_ENOUGH_MEMORY;
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

BOOLEAN QuerySystemTables(PSYSTEM_TABLES_OUTPUT Output)
{
	if (Output == NULL)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	ZeroMemory(Output, sizeof(SYSTEM_TABLES_OUTPUT));
	DWORD BytesReturned = 0;

	BOOLEAN Success = SendIoctlWithOutput(IOCTL_QUERY_SYSTEM_TABLES,
		NULL, 0, Output, sizeof(SYSTEM_TABLES_OUTPUT), &BytesReturned);
	return Success;
}

BOOLEAN QuerySystemTableEntries(ULONG TableKind, PSYSTEM_TABLE_ENTRIES_OUTPUT Output)
{
	if (Output == NULL || TableKind > SYSTEM_TABLE_KIND_GDT)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	ZeroMemory(Output, sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT));
	Output->TableKind = TableKind;
	DWORD BytesReturned = 0;
	return SendIoctlWithOutput(IOCTL_ENUM_SYSTEM_TABLE_ENTRIES, Output,
		sizeof(ULONG), Output, sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT), &BytesReturned);
}

BOOLEAN QueryPiDDBCacheEntries(PPIDDB_CACHE_ENUM_OUTPUT Output)
{
	if (Output == NULL)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	ZeroMemory(Output, sizeof(PIDDB_CACHE_ENUM_OUTPUT));
	DWORD BytesReturned = 0;
	return SendIoctlWithOutput(IOCTL_ENUM_PIDDB_CACHE, nullptr, 0,
		Output, sizeof(PIDDB_CACHE_ENUM_OUTPUT), &BytesReturned);
}

inline DWORD MultiDrvNtStatusToWin32(NTSTATUS Status)
{
	return Status == 0 ? ERROR_SUCCESS : static_cast<DWORD>(RtlNtStatusToDosError(Status));
}

BOOLEAN QueryDriverEntries(std::vector<DRIVER_ENUM_ENTRY>& Entries, PDRIVER_ENUM_HEADER Header = NULL)
{
	Entries.clear();
	if (Header != NULL)
		ZeroMemory(Header, sizeof(*Header));

	DRIVER_ENUM_HEADER Probe{};
	DWORD BytesReturned = 0;
	if (!SendIoctlWithOutput(IOCTL_ENUM_DRIVERS, NULL, 0, &Probe, sizeof(Probe), &BytesReturned))
		return FALSE;

	G_LastMultiDrvDetails.assign(Probe.Message);
	if (Header != NULL)
		*Header = Probe;
	G_LastMultiDrvError = MultiDrvNtStatusToWin32(Probe.NtStatus);
	if (Probe.NtStatus != 0 || Probe.Count == 0)
		return Probe.NtStatus == 0;

	const size_t BufferSize =
		sizeof(DRIVER_ENUM_HEADER) + (static_cast<size_t>(Probe.Count) * sizeof(DRIVER_ENUM_ENTRY));
	PDRIVER_ENUM_OUTPUT Output = static_cast<PDRIVER_ENUM_OUTPUT>(malloc(BufferSize));
	if (Output == NULL)
	{
		G_LastMultiDrvError = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}

	ZeroMemory(Output, BufferSize);
	const BOOLEAN Success = SendIoctlWithOutput(
		IOCTL_ENUM_DRIVERS, NULL, 0, Output, static_cast<DWORD>(BufferSize), &BytesReturned);
	if (Success)
	{
		G_LastMultiDrvDetails.assign(Output->Header.Message);
		G_LastMultiDrvError = MultiDrvNtStatusToWin32(Output->Header.NtStatus);
		if (Output->Header.NtStatus == 0)
			Entries.assign(Output->Entries, Output->Entries + Output->Header.Count);
	}

	free(Output);
	return Success && G_LastMultiDrvError == ERROR_SUCCESS;
}

inline bool QueryMultiDrvCapabilitiesV2(MDV2_CAPABILITIES_OUTPUT* Output)
{
	if (Output == nullptr) { G_LastMultiDrvError = ERROR_INVALID_PARAMETER; return false; }
	ZeroMemory(Output, sizeof(*Output));
	DWORD BytesReturned = 0;
	if (!SendIoctlWithOutput(IOCTL_QUERY_CAPABILITIES_V2, nullptr, 0, Output, sizeof(*Output), &BytesReturned))
		return false;
	G_LastMultiDrvError = MultiDrvNtStatusToWin32(Output->Header.Status);
	return Output->Header.Version == MDV2_PROTOCOL_VERSION && Output->Header.Status == 0;
}

inline bool QueryMultiDrvRecordsV2(DWORD Ioctl, const MDV2_QUERY_INPUT& Request,
	std::vector<MDV2_RECORD>& Records, MDV2_LIST_HEADER* ResultHeader = nullptr)
{
	Records.clear();
	MDV2_QUERY_INPUT Input = Request;
	Input.Size = sizeof(Input);
	Input.Version = MDV2_PROTOCOL_VERSION;
	if (Input.MaxEntries == 0 || Input.MaxEntries > MDV2_MAX_PAGE_RECORDS)
		Input.MaxEntries = MDV2_MAX_PAGE_RECORDS;

	MDV2_LIST_HEADER LastHeader{};
	ULONG64 Cursor = Input.Cursor;
	for (ULONG Page = 0; Page < 4096; ++Page)
	{
		Input.Cursor = Cursor;
		const size_t BufferSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) +
			static_cast<size_t>(Input.MaxEntries) * sizeof(MDV2_RECORD);
		std::vector<unsigned char> Buffer(BufferSize);
		DWORD BytesReturned = 0;
		if (!SendIoctlWithOutput(Ioctl, &Input, sizeof(Input), Buffer.data(),
			static_cast<DWORD>(Buffer.size()), &BytesReturned))
			return false;
		if (BytesReturned < sizeof(MDV2_LIST_HEADER))
		{
			G_LastMultiDrvError = ERROR_INVALID_DATA;
			return false;
		}
		const auto* Output = reinterpret_cast<const MDV2_LIST_OUTPUT*>(Buffer.data());
		LastHeader = Output->Header;
		if (LastHeader.Version != MDV2_PROTOCOL_VERSION ||
			LastHeader.ReturnedCount > Input.MaxEntries ||
			FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) +
				static_cast<size_t>(LastHeader.ReturnedCount) * sizeof(MDV2_RECORD) > BytesReturned)
		{
			G_LastMultiDrvError = ERROR_INVALID_DATA;
			return false;
		}
		Records.insert(Records.end(), Output->Records, Output->Records + LastHeader.ReturnedCount);
		if (LastHeader.NextCursor == 0 || LastHeader.NextCursor == Cursor)
			break;
		Cursor = LastHeader.NextCursor;
	}
	if (ResultHeader != nullptr) *ResultHeader = LastHeader;
	G_LastMultiDrvError = MultiDrvNtStatusToWin32(LastHeader.Status);
	return LastHeader.Version == MDV2_PROTOCOL_VERSION;
}

inline bool QueryProcessRecordsV2(ULONG ProcessId, DWORD Ioctl, std::vector<MDV2_RECORD>& Records,
	MDV2_LIST_HEADER* Header = nullptr)
{
	MDV2_QUERY_INPUT Request{};
	Request.ProcessId = ProcessId;
	Request.MaxEntries = MDV2_MAX_PAGE_RECORDS;
	return QueryMultiDrvRecordsV2(Ioctl, Request, Records, Header);
}

inline bool QueryNamedDriverRecordsV2(const std::wstring& DriverName, std::vector<MDV2_RECORD>& Records,
	MDV2_LIST_HEADER* Header = nullptr)
{
	MDV2_QUERY_INPUT Request{};
	Request.MaxEntries = MDV2_MAX_PAGE_RECORDS;
	wcsncpy_s(Request.Name, DriverName.c_str(), _TRUNCATE);
	return QueryMultiDrvRecordsV2(IOCTL_QUERY_DRIVER_V2, Request, Records, Header);
}

BOOLEAN LoadDriverKernel(const WCHAR* ServiceName, const WCHAR* ImagePath, PDRIVER_CONTROL_OUTPUT Output = NULL)
{
	if (ServiceName == NULL || ServiceName[0] == L'\0' || ImagePath == NULL || ImagePath[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DRIVER_CONTROL_INPUT Buffer{};
	wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);
	wcsncpy_s(Buffer.ImagePath, ImagePath, _TRUNCATE);

	DRIVER_CONTROL_OUTPUT Result{};
	DWORD BytesReturned = 0;
	if (!SendIoctlWithOutput(IOCTL_LOAD_DRIVER, &Buffer, sizeof(Buffer), &Result, sizeof(Result), &BytesReturned))
		return FALSE;

	G_LastMultiDrvDetails.assign(Result.Message);
	G_LastMultiDrvError = MultiDrvNtStatusToWin32(Result.NtStatus);
	if (Output != NULL)
		*Output = Result;
	return Result.NtStatus == 0;
}

	BOOLEAN UnloadDriverKernel(const WCHAR* ServiceName, BOOLEAN DeleteOnUnload, PDRIVER_CONTROL_OUTPUT Output = NULL)
{
	if (ServiceName == NULL || ServiceName[0] == L'\0')
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DRIVER_CONTROL_INPUT Buffer{};
	wcsncpy_s(Buffer.ServiceName, ServiceName, _TRUNCATE);
	Buffer.DeleteOnUnload = DeleteOnUnload;

	DRIVER_CONTROL_OUTPUT Result{};
	DWORD BytesReturned = 0;
	if (!SendIoctlWithOutput(IOCTL_UNLOAD_DRIVER, &Buffer, sizeof(Buffer), &Result, sizeof(Result), &BytesReturned))
		return FALSE;

	G_LastMultiDrvDetails.assign(Result.Message);
	G_LastMultiDrvError = MultiDrvNtStatusToWin32(Result.NtStatus);
	if (Output != NULL)
		*Output = Result;
	return Result.NtStatus == 0;
}

BOOLEAN SetProcessPreviousMode(ULONG ProcessId)
{
	if (ProcessId == 0 || ProcessId == 4)
	{
		G_LastMultiDrvError = ERROR_ACCESS_DENIED;
		return FALSE;
	}

	CRITICAL_PROCESS_INPUT Input = { 0 };
	Input.ProcessId = ProcessId;
	return SendIoctl(IOCTL_SET_PREVIOUS_MODE, &Input, sizeof(Input));
}

BOOLEAN KernelReadMemory(ULONG_PTR Address, PVOID Buffer, ULONG Size, PULONG BytesRead, KRNL_MEMRW_METHOD Method = KrnlMemRwAuto)
{
	if (BytesRead) *BytesRead = 0;
	if (Buffer == NULL || Size == 0)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD BufSz = sizeof(KERNEL_READ_OUTPUT) + Size;
	PKERNEL_READ_OUTPUT Output = (PKERNEL_READ_OUTPUT)malloc(BufSz);
	if (Output == NULL)
	{
		G_LastMultiDrvError = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}
	ZeroMemory(Output, BufSz);

	KERNEL_READ_INPUT Input = {};
	Input.Address = Address;
	Input.Size = Size;
	Input.Method = Method;

	DWORD BytesReturned = 0;
	BOOLEAN Success = SendIoctlWithOutput(IOCTL_KERNEL_READ_MEMORY, &Input, sizeof(Input),
		Output, BufSz, &BytesReturned);

	if (Success && BytesReturned > sizeof(KERNEL_READ_OUTPUT))
	{
		ULONG ActualRead = Output->BytesRead;
		if (ActualRead > Size) ActualRead = Size;
		CopyMemory(Buffer, Output->Data, ActualRead);
		if (BytesRead) *BytesRead = ActualRead;
	}
	else if (Success && Output->Status != 0)
	{
		G_LastMultiDrvError = MultiDrvNtStatusToWin32(Output->Status);
		Success = FALSE;
	}

	free(Output);
	return Success;
}

BOOLEAN KernelWriteMemory(ULONG_PTR Address, PVOID Buffer, ULONG Size, KRNL_MEMRW_METHOD Method = KrnlMemRwAuto)
{
	if (Buffer == NULL || Size == 0)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD BufSz = sizeof(KERNEL_WRITE_INPUT) + Size;
	PKERNEL_WRITE_INPUT Input = (PKERNEL_WRITE_INPUT)malloc(BufSz);
	if (Input == NULL)
	{
		G_LastMultiDrvError = ERROR_NOT_ENOUGH_MEMORY;
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

BOOLEAN DisableDse(PDSE_CONTROL_OUTPUT Output = NULL)
{
	DSE_CONTROL_OUTPUT Result = {};

	DWORD BytesReturned = 0;
	BOOLEAN Success = SendIoctlWithOutput(IOCTL_DISABLE_DSE, NULL, 0,
		&Result, sizeof(Result), &BytesReturned);

	if (Output != NULL)
		*Output = Result;

	if (Success && Result.Status != 0)
	{
		G_LastMultiDrvError = MultiDrvNtStatusToWin32(Result.Status);
		return FALSE;
	}

	return Success;
}

BOOLEAN RestoreDse(PDSE_CONTROL_OUTPUT Output = NULL)
{
	DSE_CONTROL_OUTPUT Result = {};

	DWORD BytesReturned = 0;
	BOOLEAN Success = SendIoctlWithOutput(IOCTL_RESTORE_DSE, NULL, 0,
		&Result, sizeof(Result), &BytesReturned);

	if (Output != NULL)
		*Output = Result;

	if (Success && Result.Status != 0)
	{
		G_LastMultiDrvError = MultiDrvNtStatusToWin32(Result.Status);
		return FALSE;
	}

	return Success;
}

BOOLEAN EnableDebug()
{
	return SendIoctl(IOCTL_ENABLE_DEBUG, NULL, 0);
}

BOOLEAN DisableDebug()
{
	return SendIoctl(IOCTL_DISABLE_DEBUG, NULL, 0);
}

BOOLEAN QueryDebugState(PDEBUG_STATE_OUTPUT Output)
{
	if (Output == NULL)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	ZeroMemory(Output, sizeof(*Output));
	DWORD BytesReturned = 0;
	BOOLEAN Success = SendIoctlWithOutput(IOCTL_QUERY_DEBUG_STATE, NULL, 0,
		Output, sizeof(*Output), &BytesReturned);

	if (Success && Output->Status != 0)
	{
		G_LastMultiDrvError = MultiDrvNtStatusToWin32(Output->Status);
		return FALSE;
	}

	return Success;
}

BOOL EnumerateWindowsKernel(
	_Out_writes_bytes_all_(BufferSize) PVOID Buffer,
	_In_ ULONG BufferSize,
	_Out_ PULONG EntriesReturned)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	if (Buffer == NULL || BufferSize < sizeof(KERNEL_WINDOW_ENUM_OUTPUT) || EntriesReturned == NULL)
	{
		G_LastMultiDrvError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(
		IOCTL_ENUM_WINDOWS, NULL, 0,
		Buffer, BufferSize, &BytesReturned);

	if (Success)
	{
		PKERNEL_WINDOW_ENUM_OUTPUT Out = (PKERNEL_WINDOW_ENUM_OUTPUT)Buffer;
		*EntriesReturned = Out->Count;
	}

	return Success;
}

BOOL WindowOperationKernel(
	ULONG ProcessId, ULONG64 Hwnd, ULONG Operation,
	_In_opt_ PCWSTR NewTitle,
	LONG NewX, LONG NewY, LONG NewWidth, LONG NewHeight,
	ULONG Flags)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
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

FORCEINLINE BOOL WindowKill(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_CLOSE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowHide(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_HIDE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowShow(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SHOW, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowMinimize(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_MINIMIZE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowRestore(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_RESTORE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowEnable(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_ENABLE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowDisable(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_DISABLE, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowSetTitle(ULONG Pid, ULONG64 Hwnd, PCWSTR Title, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SET_TITLE, Title, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowSetTopmost(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_SET_TOPMOST, NULL, 0, 0, 0, 0, Flags);
}

FORCEINLINE BOOL WindowRemoveTopmost(ULONG Pid, ULONG64 Hwnd, ULONG Flags = 0)
{
	return WindowOperationKernel(Pid, Hwnd, WINDOW_OP_REMOVE_TOPMOST, NULL, 0, 0, 0, 0, Flags);
}

/* ---- Command Line ---- */
BOOL GetProcessCommandLine(ULONG ProcessId, PWCHAR Buffer, ULONG MaxLen)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	if (Buffer == NULL || MaxLen < 2) { G_LastMultiDrvError = ERROR_INVALID_PARAMETER; return FALSE; }
	Buffer[0] = L'\0';

	COMMAND_LINE_INPUT Input = { ProcessId };
	ULONG OutSize = sizeof(COMMAND_LINE_INPUT) + MaxLen;
	PBYTE OutBuf = new BYTE[OutSize];
	RtlZeroMemory(OutBuf, OutSize);

	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(IOCTL_GET_COMMAND_LINE, &Input, sizeof(Input),
		OutBuf, OutSize, &BytesReturned);
	if (Success)
	{
		ULONG CopyLen = (BytesReturned > 0 && BytesReturned <= MaxLen - 2) ? BytesReturned : 0;
		if (CopyLen > 0)
			RtlCopyMemory(Buffer, OutBuf, CopyLen);
	}
	delete[] OutBuf;
	return Success;
}

/* ---- Service ---- */
BOOL ServiceKernelOp(PCWSTR Name, ULONG Op, ULONG SvcType)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	SERVICE_OPERATION_INPUT Input = {};
	Input.Operation = Op;
	Input.ServiceType = SvcType;
	wcsncpy_s(Input.ServiceName, 128, Name, 127);
	return SendIoctl(IOCTL_SERVICE_OPERATION, &Input, sizeof(Input));
}

FORCEINLINE BOOL ServiceStart(PCWSTR Name, ULONG Type = 1) { return ServiceKernelOp(Name, 0, Type); }
FORCEINLINE BOOL ServiceStop(PCWSTR Name, ULONG Type = 1) { return ServiceKernelOp(Name, 1, Type); }
FORCEINLINE BOOL ServiceDisable(PCWSTR Name) { return ServiceKernelOp(Name, 2, 0); }
FORCEINLINE BOOL ServiceEnable(PCWSTR Name) { return ServiceKernelOp(Name, 3, 0); }
FORCEINLINE BOOL ServiceDelete(PCWSTR Name) { return ServiceKernelOp(Name, 4, 0); }

/* ---- Registry ---- */
BOOL RegistryKernelOp(PCWSTR KeyPath, ULONG Op, PCWSTR ValueName, ULONG ValueType,
	PVOID ValueData, ULONG ValueSize, PVOID OutBuf, ULONG OutSize, PULONG Returned)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	ULONG InSize = sizeof(REG_OPERATION_INPUT) + ValueSize;
	PBYTE InBuf = new BYTE[InSize];
	RtlZeroMemory(InBuf, InSize);
	PREG_OPERATION_INPUT RegIn = (PREG_OPERATION_INPUT)InBuf;
	RegIn->Operation = Op;
	wcsncpy_s(RegIn->KeyPath, 260, KeyPath, 259);
	if (ValueName) wcsncpy_s(RegIn->ValueName, 128, ValueName, 127);
	RegIn->ValueType = ValueType;
	RegIn->ValueDataSize = ValueSize;
	if (ValueData && ValueSize) RtlCopyMemory(InBuf + sizeof(REG_OPERATION_INPUT), ValueData, ValueSize);

	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(IOCTL_REG_OPERATION, InBuf, InSize, OutBuf, OutSize, &BytesReturned);
	if (Returned) *Returned = BytesReturned;
	delete[] InBuf;
	return Success;
}

FORCEINLINE BOOL RegEnumSubkeys(PCWSTR KeyPath, PVOID OutBuf, ULONG OutSize, PULONG Returned)
{ return RegistryKernelOp(KeyPath, 0, NULL, 0, NULL, 0, OutBuf, OutSize, Returned); }
FORCEINLINE BOOL RegDeleteKey(PCWSTR KeyPath)
{ return RegistryKernelOp(KeyPath, 1, NULL, 0, NULL, 0, NULL, 0, NULL); }
FORCEINLINE BOOL RegSetValueKernel(PCWSTR KeyPath, PCWSTR ValName, ULONG Type, PVOID Data, ULONG Size)
{ return RegistryKernelOp(KeyPath, 2, ValName, Type, Data, Size, NULL, 0, NULL); }
FORCEINLINE BOOL RegCreateKeyKernel(PCWSTR KeyPath)
{ return RegistryKernelOp(KeyPath, 3, NULL, 0, NULL, 0, NULL, 0, NULL); }
FORCEINLINE BOOL RegDeleteValueKernel(PCWSTR KeyPath, PCWSTR ValName)
{ return RegistryKernelOp(KeyPath, 4, ValName, 0, NULL, 0, NULL, 0, NULL); }

/* ---- Session ---- */
BOOL SessionKernelOp(ULONG SessionId, ULONG Op, PVOID OutBuf, ULONG OutSize, PULONG Returned)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	SESSION_OPERATION_INPUT Input = { SessionId, Op };
	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(IOCTL_SESSION_OPERATION, &Input, sizeof(Input),
		OutBuf, OutSize, &BytesReturned);
	if (Returned) *Returned = BytesReturned;
	return Success;
}

FORCEINLINE BOOL EnumSessions(PVOID OutBuf, ULONG OutSize, PULONG Returned)
{ return SessionKernelOp(0, 0, OutBuf, OutSize, Returned); }
FORCEINLINE BOOL LogoffSession(ULONG SessionId)
{ return SessionKernelOp(SessionId, 1, NULL, 0, NULL); }

/* ---- Mitigation ---- */
BOOL QueryMitigationKernel(ULONG Pid, PVOID OutBuf, ULONG OutSize, PULONG Returned)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(IOCTL_MITIGATION_QUERY, &Pid, sizeof(ULONG),
		OutBuf, OutSize, &BytesReturned);
	if (Returned) *Returned = BytesReturned;
	return Success;
}

BOOL SetMitigationKernel(ULONG Pid, ULONG PolicyId, ULONG64 Flags)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	MITIGATION_SET_INPUT Input = { Pid, PolicyId, Flags };
	return SendIoctl(IOCTL_MITIGATION_SET, &Input, sizeof(Input));
}

/* ---- Sync Objects ---- */
BOOL EnumSyncObjectsKernel(PVOID OutBuf, ULONG OutSize, PULONG Count)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	DWORD BytesReturned = 0;
	BOOL Success = SendIoctlWithOutput(IOCTL_ENUM_SYNC_OBJECTS, NULL, 0,
		OutBuf, OutSize, &BytesReturned);
	if (Count) *Count = BytesReturned;
	return Success;
}

/* ---- Firewall ---- */
BOOL FirewallKernelOp(PCWSTR RuleName, ULONG Op, ULONG Action, ULONG Port, ULONG Protocol)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	FIREWALL_OPERATION_INPUT Input = {};
	Input.Operation = Op;
	Input.Action = Action;
	Input.RemotePort = Port;
	Input.Protocol = Protocol;
	wcsncpy_s(Input.RuleName, 128, RuleName ? RuleName : L"", 127);
	return SendIoctl(IOCTL_FIREWALL_OPERATION, &Input, sizeof(Input));
}

/* ---- Window Protect ---- */
BOOL ProtectWindowKernel(ULONG Pid, ULONG64 Hwnd, ULONG Flags)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	WINDOW_PROTECT_INPUT Input = { Pid, Hwnd, Flags ? Flags : WINPROT_ALL };
	return SendIoctl(IOCTL_ADD_WINDOW_PROTECT, &Input, sizeof(Input));
}

BOOL UnprotectWindowKernel(ULONG Pid, ULONG64 Hwnd)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	WINDOW_PROTECT_INPUT Input = { Pid, Hwnd, 0 };
	return SendIoctl(IOCTL_REMOVE_WINDOW_PROTECT, &Input, sizeof(Input));
}

/* ---- Injection Protection (no PPL) ---- */
BOOL AddInjectionProtectKernel(ULONG Pid)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	INJECTION_PROTECT_INPUT Input = { Pid };
	return SendIoctl(IOCTL_ADD_INJECTION_PROTECTION, &Input, sizeof(Input));
}

BOOL RemoveInjectionProtectKernel(ULONG Pid)
{
	G_LastMultiDrvError = ERROR_SUCCESS;
	INJECTION_PROTECT_INPUT Input = { Pid };
	return SendIoctl(IOCTL_REMOVE_INJECTION_PROTECTION, &Input, sizeof(Input));
}
