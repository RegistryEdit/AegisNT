#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <bcrypt.h>
#include "../Driver.h"
#include <stdarg.h>
#include <stdio.h>

#define DBG 1; 

#ifdef _M_AMD64

static VOID
SidtEmulate(
	_Out_writes_bytes_(10) PVOID Destination
)
{
	typedef VOID (*PEmuFn)(PVOID);
	static const UCHAR Code[] = {
		0x0F, 0x01, 0x09,   
		0xC3                 
	};
	PEmuFn Fn = reinterpret_cast<PEmuFn>(ExAllocatePool2(
		POOL_FLAG_NON_PAGED_EXECUTE, sizeof(Code), 'diGS'));
	if (Fn == NULL) return;
	RtlCopyMemory(Fn, Code, sizeof(Code));
	Fn(Destination);
	ExFreePoolWithTag(Fn, 'diGS');
}

static VOID
SgdtEmulate(
	_Out_writes_bytes_(10) PVOID Destination
)
{	
	typedef VOID (*PEmuFn)(PVOID);
	static const UCHAR Code[] = {
		0x0F, 0x01, 0x01,   
		0xC3                 
	};
	PEmuFn Fn = reinterpret_cast<PEmuFn>(ExAllocatePool2(
		POOL_FLAG_NON_PAGED_EXECUTE, sizeof(Code), 'tdGS'));
	if (Fn == NULL) return;
	RtlCopyMemory(Fn, Code, sizeof(Code));
	Fn(Destination);
	ExFreePoolWithTag(Fn, 'tdGS');
}

static ULONG64
ReadMsrEmulate(
	_In_ ULONG MsrRegister
)
{
	typedef ULONG64 (*PReadMsrFn)(ULONG);
	static const UCHAR Code[] = {
		0x8B, 0xC1,          
		0x0F, 0x32,          
		0x48, 0xC1, 0xE2, 0x20, 
		0x48, 0x0B, 0xC2,    
		0xC3                  
	};
	PReadMsrFn Fn = reinterpret_cast<PReadMsrFn>(ExAllocatePool2(
		POOL_FLAG_NON_PAGED_EXECUTE, sizeof(Code), 'srMR'));
	if (Fn == NULL) return 0;
	RtlCopyMemory(Fn, Code, sizeof(Code));
	ULONG64 Result = Fn(MsrRegister);
	ExFreePoolWithTag(Fn, 'srMR');
	return Result;
}

#endif

#ifdef _M_AMD64
#define EPROCESS_SCAN_START 0x600
#else
#define EPROCESS_SCAN_START 0x200
#endif

#ifndef MM_COPY_MEMORY_VIRTUAL
#define MM_COPY_MEMORY_VIRTUAL   0x2
#define MM_COPY_MEMORY_PHYSICAL  0x1

typedef union _MM_COPY_ADDRESS {
	PVOID            VirtualAddress;
	PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS;
#endif 

typedef NTSTATUS (NTAPI *PMdvMmCopyMemory_t)(
	_Out_writes_bytes_all_(NumberOfBytes) PVOID TargetAddress,
	_In_                         MM_COPY_ADDRESS SourceAddress,
	_In_                         SIZE_T         NumberOfBytes,
	_In_                         ULONG          Flags,
	_Out_opt_                    PSIZE_T        NumberOfBytesTransferred
	);

static PMdvMmCopyMemory_t G_pMmCopyMemory = NULL;

typedef NTSTATUS(NTAPI *PZwCreateProcess_t)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ BOOLEAN InheritObjectTable,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort
	);

typedef NTSTATUS(NTAPI* PZwCreateProcessEx_t)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort,
	_In_ ULONG JobMemberLevel
	);

typedef NTSTATUS(NTAPI *PZwCreateThreadEx_t)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
	);

typedef NTSTATUS(NTAPI* PRtlCreateUserThread_t)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
	_In_ BOOLEAN CreateSuspended,
	_In_ ULONG StackZeroBits,
	_In_opt_ PULONG StackReserved,
	_In_opt_ PULONG StackCommit,
	_In_ PVOID StartAddress,
	_In_opt_ PVOID StartParameter,
	_Out_opt_ PHANDLE ThreadHandle,
	_Out_opt_ PCLIENT_ID ClientId
	);

typedef NTSTATUS(NTAPI* PZwCreateUserProcess_t)(
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK ProcessDesiredAccess,
	_In_ ACCESS_MASK ThreadDesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
	_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
	_In_ ULONG ProcessFlags,
	_In_ ULONG ThreadFlags,
	_In_opt_ PVOID ProcessParameters,
	_Inout_ PVOID CreateInfo,
	_In_opt_ PVOID AttributeList
	);

typedef NTSTATUS(NTAPI* PRtlCreateProcessParametersEx_t)(
	_Out_ PVOID* ProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags
	);

typedef VOID(NTAPI* PRtlDestroyProcessParameters_t)(
	_In_ PVOID ProcessParameters
	);

static PZwCreateProcess_t   G_pZwCreateProcess = NULL;
static PZwCreateProcessEx_t G_pZwCreateProcessEx = NULL;
static PZwCreateThreadEx_t  G_pZwCreateThreadEx = NULL;
static PRtlCreateUserThread_t G_pRtlCreateUserThread = NULL;
static PZwCreateUserProcess_t G_pZwCreateUserProcess = NULL;
static PRtlCreateProcessParametersEx_t G_pRtlCreateProcessParametersEx = NULL;
static PRtlDestroyProcessParameters_t G_pRtlDestroyProcessParameters = NULL;

typedef NTSTATUS(NTAPI *PZwAllocateVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);

static PZwAllocateVirtualMemory_t G_pZwAllocateVirtualMemory = NULL;

#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001UL
#endif

#define MDV_PS_ATTRIBUTE_IMAGE_NAME      ((ULONG_PTR)0x00020005)
#define MDV_PS_ATTRIBUTE_PARENT_PROCESS  ((ULONG_PTR)0x00060000)
#define MDV_PS_ATTRIBUTE_TOKEN           ((ULONG_PTR)0x00020002)

typedef enum _MDV_PS_CREATE_STATE {
	MdvPsCreateInitialState = 0,
	MdvPsCreateFailOnFileOpen = 1,
	MdvPsCreateFailOnSectionCreate = 2,
	MdvPsCreateFailExeFormat = 3,
	MdvPsCreateFailMachineMismatch = 4,
	MdvPsCreateFailExeName = 5,
	MdvPsCreateSuccess = 6,
	MdvPsCreateMaximumStates = 7
} MDV_PS_CREATE_STATE;

typedef struct _MDV_PS_ATTRIBUTE {
	ULONG_PTR Attribute;
	SIZE_T    Size;
	union {
		ULONG_PTR Value;
		PVOID     ValuePtr;
	};
	PSIZE_T ReturnLength;
} MDV_PS_ATTRIBUTE, * PMDV_PS_ATTRIBUTE;

typedef struct _MDV_PS_CREATE_INFO {
	SIZE_T Size;
	MDV_PS_CREATE_STATE State;
	union {
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		struct {
			HANDLE FileHandle;
		} FailSection;
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		struct {
			HANDLE IFEOKey;
		} ExeName;
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1;
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} MDV_PS_CREATE_INFO, * PMDV_PS_CREATE_INFO;

#define POOL_TAG 'drGP'
#define MAX_PROTECTED_PROCESSES  256
#define MAX_PROTECTED_REGISTRY   128
#define MAX_PROTECTED_FILES      128

typedef struct _MY_MODULE_ENTRY {
	HANDLE  Section;
	PVOID   MappedBase;
	PVOID   ImageBase;
	ULONG   ImageSize;
	ULONG   Flags;
	USHORT  LoadOrderIndex;
	USHORT  InitOrderIndex;
	USHORT  LoadCount;
	USHORT  OffsetToFileName;
	UCHAR   FullPathName[256];
} MY_MODULE_ENTRY, * PMY_MODULE_ENTRY;

typedef struct _MY_MODULE_INFO {
	ULONG          ModulesCount;
	MY_MODULE_ENTRY Modules[1];
} MY_MODULE_INFO, * PMY_MODULE_INFO;

static __forceinline PVOID
AllocPoolZero(
	_In_ SIZE_T Size
)
{
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, POOL_TAG);
}

static PMY_MODULE_INFO GetSystemModuleInfo(VOID);
static BOOLEAN IsAddressInSystemModule(_In_ PVOID Address, _In_ PMY_MODULE_INFO ModuleInfo);
static BOOLEAN GetNtoskrnlInfo(_Out_ PULONG_PTR Base, _Out_ PULONG Size);
static ULONG_PTR FindLdrInitRva(VOID);
static PVOID GetProcessNtdllBase(_In_ PEPROCESS Process);
static NTSTATUS SetupProcessParamsInTarget(_In_ PEPROCESS Process, _In_ PCWSTR ImagePath);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FindPplOffset)
#pragma alloc_text(PAGE, SetProcessPpl)
#pragma alloc_text(PAGE, RemoveProcessPpl)
#pragma alloc_text(PAGE, QueryProcessPpl)
#pragma alloc_text(PAGE, SetProcessCritical)
#pragma alloc_text(PAGE, RemoveProcessCritical)
#pragma alloc_text(PAGE, DisableProcessApc)
#pragma alloc_text(PAGE, EnableProcessApc)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(INIT, DriverEntry)
#endif

typedef NTSTATUS(NTAPI* PSE_LOCATE_PROCESS_IMAGE_NAME)(
	_In_ PEPROCESS Process,
	_Outptr_ PUNICODE_STRING* ImageFileName
	);

#define MDV_AUTHORIZED_FILE_CONTEXT ((PVOID)(ULONG_PTR)0x4D445641u) 

static const UCHAR G_AllowedImageSha256[32] = {
	0xD7, 0x39, 0xDC, 0x9B, 0x09, 0x8C, 0x9D, 0x92,
	0xA6, 0xBD, 0x8E, 0xCC, 0xE0, 0x4F, 0x34, 0x5A,
	0x72, 0x83, 0x99, 0x78, 0x0B, 0xFD, 0x13, 0x71,
	0x7A, 0xA2, 0x6C, 0x40, 0xE4, 0xF1, 0x49, 0x8F,
};

static NTSTATUS VerifyRequestorImageSignature(_In_ PIRP Irp);
static NTSTATUS HashImageFileSha256(_In_ PCUNICODE_STRING ImagePath, _Out_writes_(32) PUCHAR Digest);

typedef struct _PROTECTED_PROCESS_ENTRY {
	LIST_ENTRY ListEntry;
	ULONG      ProcessId;
} PROTECTED_PROCESS_ENTRY, * PPROTECTED_PROCESS_ENTRY;

typedef struct _PROTECTED_REGISTRY_ENTRY {
	LIST_ENTRY ListEntry;
	WCHAR      KeyPath[256];
} PROTECTED_REGISTRY_ENTRY, * PPROTECTED_REGISTRY_ENTRY;

typedef struct _PROTECTED_FILE_ENTRY {
	LIST_ENTRY ListEntry;
	WCHAR      FilePath[260];
} PROTECTED_FILE_ENTRY, * PPROTECTED_FILE_ENTRY;

typedef struct _HIDDEN_PROCESS_ENTRY {
	LIST_ENTRY  ListEntry;
	ULONG       ProcessId;
	PLIST_ENTRY SavedFlink;
	PLIST_ENTRY SavedBlink;
} HIDDEN_PROCESS_ENTRY, * PHIDDEN_PROCESS_ENTRY;

typedef struct _APC_TOGGLE_ENTRY {
	LIST_ENTRY ListEntry;
	ULONG      ProcessId;
	HANDLE     ThreadId;
	SHORT      OriginalKernelApcDisable;
	BOOLEAN    Active;
	UCHAR      Reserved[5];
} APC_TOGGLE_ENTRY, * PAPC_TOGGLE_ENTRY;

typedef struct _PROTECTED_WINDOW_ENTRY {
	LIST_ENTRY ListEntry;
	UINT64     Hwnd;
	ULONG      ProcessId;
	ULONG      ProtectionFlags;
	ULONG      StyleSnapshot;
	ULONG      ExStyleSnapshot;
	WCHAR      TitleSnapshot[128];
} PROTECTED_WINDOW_ENTRY, * PPROTECTED_WINDOW_ENTRY;

#define WINPROT_CLOSE    0x00000001
#define WINPROT_HIDE     0x00000002
#define WINPROT_TITLE    0x00000004
#define WINPROT_DISABLE  0x00000008
#define WINPROT_MOVE     0x00000010
#define WINPROT_RESIZE   0x00000020
#define WINPROT_TOPMOST  0x00000040
#define WINPROT_ALL      0xFFFFFFFF

static ULONG GetWindowProtectionFlags(_In_ UINT64 Hwnd);

static LIST_ENTRY       G_ProcessListHead = { 0 };
static KSPIN_LOCK       G_ProcessListLock = { 0 };
static ULONG            G_ProcessCount = 0;

static LIST_ENTRY       G_RegistryListHead = { 0 };
static KSPIN_LOCK       G_RegistryListLock = { 0 };
static ULONG            G_RegistryCount = 0;

static LIST_ENTRY       G_FileListHead = { 0 };
static KSPIN_LOCK       G_FileListLock = { 0 };
static ULONG            G_FileCount = 0;

static PVOID            G_ObCallbackHandle = NULL;
static LARGE_INTEGER    G_CmCallbackCookie = { 0 };
static PFLT_FILTER      G_FilterHandle = NULL;
static PVOID            G_PsProcessNotifyHandle = NULL;
static PVOID            G_PsThreadNotifyHandle = NULL;
static PVOID            G_PsImageNotifyHandle = NULL;
static BOOLEAN          G_BugCheckCallbackActive = FALSE;
static BOOLEAN          G_ShutdownCallbackActive = FALSE;
static BOOLEAN          G_BugCheckReasonCallbackActive = FALSE;
static KBUGCHECK_CALLBACK_RECORD G_BugCheckCallbackRecord = {};
static KBUGCHECK_REASON_CALLBACK_RECORD G_BugCheckReasonCallbackRecord = {};
static ULONG            G_BugCheckCallbackBuffer = 0;
static ULONG            G_PplOffset = 0;
static PDEVICE_OBJECT   G_DeviceObject = NULL;
static BOOLEAN          G_ObCallbacksActive = FALSE;
static BOOLEAN          G_CmCallbackActive = FALSE;
static BOOLEAN          G_FltFilterActive = FALSE;
static BOOLEAN          G_Initialized = FALSE;
static ULONG            G_ObCallbackListOffset = 0;
static PLIST_ENTRY      G_CmCallbackListHead = NULL;
static volatile LONG     G_RemoveFiltersInProgress = 0;

static LIST_ENTRY       G_InjectionProtectListHead = { 0 };
static KSPIN_LOCK       G_InjectionProtectListLock = { 0 };
static ULONG            G_InjectionProtectCount = 0;

static LIST_ENTRY       G_HiddenProcessListHead = { 0 };
static KSPIN_LOCK       G_HiddenProcessListLock = { 0 };
static ULONG            G_ActiveProcessLinksOffset = 0;
static BOOLEAN          G_ActiveLinksOffsetFound = FALSE;
static LIST_ENTRY       G_ApcToggleListHead = { 0 };
static KSPIN_LOCK       G_ApcToggleListLock = { 0 };
static ULONG            G_ApcToggleCount = 0;
static LIST_ENTRY       G_WindowListHead = { 0 };
static KSPIN_LOCK       G_WindowListLock = { 0 };
static ULONG            G_WindowCount = 0;
static ULONG            G_KernelApcDisableOffset = 0;
static BOOLEAN          G_KernelApcDisableFound  = FALSE;
static ULONG            G_TokenOffset        = 0;
static BOOLEAN          G_TokenOffsetFound   = FALSE;

static NTSTATUS FindTokenOffset(_Out_ PULONG Offset, _In_opt_ PEPROCESS CompareProcess);
static NTSTATUS CreateProcessFromSection(_Out_ PHANDLE ProcessHandle, _In_ HANDLE ParentProcessHandle, _In_ HANDLE SectionHandle);

#ifndef AEGISCORE_ENABLE_LOGGING
#if DBG
#define AEGISCORE_ENABLE_LOGGING 1
#else
#define AEGISCORE_ENABLE_LOGGING 1
#endif
#endif

VOID
LogMessage(
	_In_ PCCH Format,
	_In_ ...
)
{
#if AEGISCORE_ENABLE_LOGGING
	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	int N = _vsnprintf_s(Message, sizeof(Message) - sizeof(CHAR), Format, VaList);
	va_end(VaList);
	if (N >= 0 && (size_t)N < sizeof(Message))
		Message[N] = '\0';
	else
		Message[sizeof(Message) - 1] = '\0';

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AegisCore] %s", Message);
#else
	UNREFERENCED_PARAMETER(Format);
#endif
}

static NTSTATUS
FindTokenOffset(
	_Out_ PULONG Offset,
	_In_opt_ PEPROCESS CompareProcess
)
{
	*Offset = 0;

	PEPROCESS SystemProcess = NULL;
	PACCESS_TOKEN SystemToken = NULL;
	PACCESS_TOKEN CompareToken = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(4), &SystemProcess);
	if (!NT_SUCCESS(Status))
		return Status;

	SystemToken = PsReferencePrimaryToken(SystemProcess);
	if (SystemToken == NULL)
	{
		ObfDereferenceObject(SystemProcess);
		return STATUS_ACCESS_DENIED;
	}

	if (CompareProcess != NULL)
	{
		CompareToken = PsReferencePrimaryToken(CompareProcess);
		if (CompareToken == NULL)
		{
			PsDereferencePrimaryToken(SystemToken);
			ObfDereferenceObject(SystemProcess);
			return STATUS_ACCESS_DENIED;
		}
	}

	static const ULONG KnownOffsets[] = {
		0x4B8,  
		0x360,  
		0x358,  
	};

	for (ULONG i = 0; i < ARRAYSIZE(KnownOffsets); i++)
	{
		ULONG Candidate = KnownOffsets[i];
		ULONG_PTR SysVal = 0;
		__try
		{
			SysVal = *(volatile ULONG_PTR*)((PUCHAR)SystemProcess + Candidate);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}

		if ((SysVal & ~0xFULL) != (ULONG_PTR)SystemToken)
			continue;

		if (CompareProcess != NULL)
		{
			ULONG_PTR CmpVal = 0;
			__try
			{
				CmpVal = *(volatile ULONG_PTR*)((PUCHAR)CompareProcess + Candidate);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
			if ((CmpVal & ~0xFULL) != (ULONG_PTR)CompareToken)
				continue;
		}

		*Offset = Candidate;
		LogMessage("FindTokenOffset: known offset 0x%X matched.\n", Candidate);
		goto Cleanup;
	}

	{
		static const ULONG RetryCount = 3;
		for (ULONG Attempt = 0; Attempt < RetryCount; Attempt++)
		{
			for (ULONG Candidate = 0x200; Candidate < PAGE_SIZE * 2; Candidate += sizeof(ULONG_PTR))
			{
				ULONG_PTR SystemValue = 0;
				ULONG_PTR CompareValue = 0;
				__try
				{
					SystemValue = *(volatile ULONG_PTR*)((PUCHAR)SystemProcess + Candidate);
					if (CompareProcess != NULL)
						CompareValue = *(volatile ULONG_PTR*)((PUCHAR)CompareProcess + Candidate);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					continue;
				}

				if ((SystemValue & ~0xFULL) != (ULONG_PTR)SystemToken)
					continue;

				if (CompareProcess != NULL)
				{
					if ((CompareValue & ~0xFULL) != (ULONG_PTR)CompareToken)
						continue;
				}

				*Offset = Candidate;
				goto Cleanup;
			}

			if (Attempt + 1 < RetryCount)
			{
				LARGE_INTEGER Delay;
				Delay.QuadPart = -10000; 
				KeDelayExecutionThread(KernelMode, FALSE, &Delay);
			}
		}
	}

Cleanup:
	if (CompareToken != NULL)
		PsDereferencePrimaryToken(CompareToken);
	PsDereferencePrimaryToken(SystemToken);
	ObfDereferenceObject(SystemProcess);

	return *Offset != 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS
CreateProcessFromSection(
	_Out_ PHANDLE ProcessHandle,
	_In_ HANDLE ParentProcessHandle,
	_In_ HANDLE SectionHandle
)
{
	if (ProcessHandle == NULL || ParentProcessHandle == NULL || SectionHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	if (G_pZwCreateProcess == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"ZwCreateProcess");
		G_pZwCreateProcess = (PZwCreateProcess_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pZwCreateProcessEx == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"ZwCreateProcessEx");
		G_pZwCreateProcessEx = (PZwCreateProcessEx_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pZwCreateProcess != NULL)
	{
		LogMessage("LaunchAs: using ZwCreateProcess.\n");
		return G_pZwCreateProcess(ProcessHandle,
			MAXIMUM_ALLOWED, NULL, ParentProcessHandle, FALSE, SectionHandle, NULL, NULL);
	}

	if (G_pZwCreateProcessEx != NULL)
	{
		LogMessage("LaunchAs: using ZwCreateProcessEx.\n");
		return G_pZwCreateProcessEx(ProcessHandle,
			MAXIMUM_ALLOWED, NULL, ParentProcessHandle, 0, SectionHandle, NULL, NULL, 0);
	}

	LogMessage("LaunchAs: neither ZwCreateProcess nor ZwCreateProcessEx is available.\n");
	return STATUS_PROCEDURE_NOT_FOUND;
}

static NTSTATUS
CreateInitialThreadInProcess(
	_Out_opt_ PHANDLE ThreadHandle,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine
)
{
	if (ProcessHandle == NULL || StartRoutine == NULL)
		return STATUS_INVALID_PARAMETER;

	if (G_pZwCreateThreadEx == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"ZwCreateThreadEx");
		G_pZwCreateThreadEx = (PZwCreateThreadEx_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pRtlCreateUserThread == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"RtlCreateUserThread");
		G_pRtlCreateUserThread = (PRtlCreateUserThread_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pZwCreateThreadEx != NULL)
	{
		LogMessage("LaunchAs: using ZwCreateThreadEx.\n");
		return G_pZwCreateThreadEx(ThreadHandle,
			MAXIMUM_ALLOWED, NULL, ProcessHandle,
			StartRoutine, NULL, 0, 0, 0, 0, NULL);
	}

	if (G_pRtlCreateUserThread != NULL)
	{
		LogMessage("LaunchAs: using RtlCreateUserThread.\n");
		return G_pRtlCreateUserThread(ProcessHandle,
			NULL, FALSE, 0, NULL, NULL,
			StartRoutine, NULL, ThreadHandle, NULL);
	}

	LogMessage("LaunchAs: neither ZwCreateThreadEx nor RtlCreateUserThread is available.\n");
	return STATUS_PROCEDURE_NOT_FOUND;
}
