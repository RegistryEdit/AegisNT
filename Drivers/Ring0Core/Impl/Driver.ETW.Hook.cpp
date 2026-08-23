
#define EtwpStartTrace   1
#define EtwpStopTrace    2
#define EtwpUpdateTrace  4

#define WNODE_FLAG_TRACED_GUID        0x00020000
#define EVENT_TRACE_BUFFERING_MODE    0x00000400
#define EVENT_TRACE_FLAG_SYSTEMCALL   0x00000080
#define SystemPerformanceTraceInformation  31

#pragma pack(push, 8)
typedef struct _MY_ETW_TRACE_PROPERTIES {
	
	ULONG        WnodeBufferSize;
	ULONG        WnodeProviderId;
	union { ULONG64 HistoricalContext; struct { ULONG Version; ULONG Linkage; }; };
	union { ULONG CountLost; HANDLE KernelHandle; LARGE_INTEGER TimeStamp; };
	GUID         WnodeGuid;
	ULONG        WnodeClientContext;
	ULONG        WnodeFlags;
	
	ULONG        BufferSize;
	ULONG        MinimumBuffers;
	ULONG        MaximumBuffers;
	ULONG        MaximumFileSize;
	ULONG        LogFileMode;
	ULONG        FlushTimer;
	ULONG        EnableFlags;
	LONG         AgeLimit;
	ULONG        NumberOfBuffers;
	ULONG        FreeBuffers;
	ULONG        EventsLost;
	ULONG        BuffersWritten;
	ULONG        LogBuffersLost;
	ULONG        RealTimeBuffersLost;
	HANDLE       LoggerThreadId;
	ULONG        LogFileNameOffset;
	ULONG        LoggerNameOffset;
	
	ULONG64      Unknown[3];
	UNICODE_STRING ProviderName;
} MY_ETW_TRACE_PROPERTIES;
#pragma pack(pop)

typedef MY_ETW_TRACE_PROPERTIES* PMY_ETW_TRACE_PROPERTIES;

typedef enum _MY_ETW_INFO_CLASS {
	MyEtwiProfileCounterList = 15,
	MyEtwiProfileEventList   = 16,
} MY_ETW_INFO_CLASS;

typedef struct _MY_PROFILE_COUNTER_INFO {
	MY_ETW_INFO_CLASS InfoClass;
	HANDLE TraceHandle;
	ULONG  ProfileSource[1];
} MY_PROFILE_COUNTER_INFO;

typedef struct _MY_SYSTEM_EVENT_INFO {
	MY_ETW_INFO_CLASS InfoClass;
	HANDLE TraceHandle;
	ULONG  HookId[1];
} MY_SYSTEM_EVENT_INFO;

#pragma pack(push, 8)
typedef struct _MY_KDDEBUGGER_DATA64 {
	LIST_ENTRY64 HeaderList;
	ULONG        HeaderOwnerTag;
	ULONG        HeaderSize;
	ULONG64      KernBase;
	ULONG64      BreakpointWithStatus;
	ULONG64      SavedContext;
	USHORT       ThCallbackStack;
	USHORT       NextCallback;
	USHORT       FramePointer;
	USHORT       PaeEnabled;
	ULONG64      KiCallUserMode;
	ULONG64      KeUserCallbackDispatcher;
	ULONG64      PsLoadedModuleList;
	ULONG64      PsActiveProcessHead;
	ULONG64      PspCidTable;
	ULONG64      ExpSystemResourcesList;
	ULONG64      ExpPagedPoolDescriptor;
	ULONG64      ExpNumberOfPagedPools;
	ULONG64      KeTimeIncrement;
	ULONG64      KeBugCheckCallbackListHead;
	ULONG64      KiBugcheckData;
	ULONG64      IopErrorLogListHead;
	ULONG64      ObpRootDirectoryObject;
	ULONG64      ObpTypeObjectType;
	ULONG64      MmSystemCacheStart;
	ULONG64      MmSystemCacheEnd;
	ULONG64      MmSystemCacheWs;
	ULONG64      MmPfnDatabase;
	ULONG64      MmSystemPtesStart;
	ULONG64      MmSystemPtesEnd;
	ULONG64      MmSubsectionBase;
	ULONG64      MmNumberOfPagingFiles;
	ULONG64      MmLowestPhysicalPage;
	ULONG64      MmHighestPhysicalPage;
	ULONG64      MmNumberOfPhysicalPages;
	ULONG64      MmMaximumNonPagedPoolInBytes;
	ULONG64      MmNonPagedSystemStart;
	ULONG64      MmNonPagedPoolStart;
	ULONG64      MmNonPagedPoolEnd;
	ULONG64      MmPagedPoolStart;
	ULONG64      MmPagedPoolEnd;
	ULONG64      MmPagedPoolInformation;
	ULONG64      MmPageSize;
	ULONG64      MmSizeOfPagedPoolInBytes;
	ULONG64      MmTotalCommitLimit;
	ULONG64      MmTotalCommittedPages;
	ULONG64      MmSharedCommit;
	ULONG64      MmDriverCommit;
	ULONG64      MmProcessCommit;
	ULONG64      MmPagedPoolCommit;
	ULONG64      MmExtendedCommit;
	ULONG64      MmZeroedPageListHead;
	ULONG64      MmFreePageListHead;
	ULONG64      MmStandbyPageListHead;
	ULONG64      MmModifiedPageListHead;
	ULONG64      MmModifiedNoWritePageListHead;
	ULONG64      MmAvailablePages;
	ULONG64      MmResidentAvailablePages;
	ULONG64      PoolTrackTable;
	ULONG64      NonPagedPoolDescriptor;
	ULONG64      MmHighestUserAddress;
	ULONG64      MmSystemRangeStart;
	ULONG64      MmUserProbeAddress;
	ULONG64      KdPrintCircularBuffer;
	ULONG64      KdPrintCircularBufferEnd;
	ULONG64      KdPrintWritePointer;
	ULONG64      KdPrintRolloverCount;
	ULONG64      MmLoadedUserImageList;
	ULONG64      NtBuildLab;
	ULONG64      KiNormalSystemCall;
	ULONG64      KiProcessorBlock;
	ULONG64      MmUnloadedDrivers;
	ULONG64      MmLastUnloadedDriver;
	ULONG64      MmTriageActionTaken;
	ULONG64      MmSpecialPoolTag;
	ULONG64      KernelVerifier;
	ULONG64      MmVerifierData;
	ULONG64      MmAllocatedNonPagedPool;
	ULONG64      MmPeakCommitment;
	ULONG64      MmTotalCommitLimitMaximum;
	ULONG64      CmNtCSDVersion;
	ULONG64      MmPhysicalMemoryBlock;
	ULONG64      MmSessionBase;
	ULONG64      MmSessionSize;
	ULONG64      MmSystemParentTablePage;
	ULONG64      MmVirtualTranslationBase;
	USHORT       OffsetKThreadNextProcessor;
	USHORT       OffsetKThreadTeb;
	USHORT       OffsetKThreadKernelStack;
	USHORT       OffsetKThreadInitialStack;
	USHORT       OffsetKThreadApcProcess;
	USHORT       OffsetKThreadState;
	USHORT       OffsetKThreadBStore;
	USHORT       OffsetKThreadBStoreLimit;
	USHORT       SizeEProcess;
	USHORT       OffsetEprocessPeb;
	USHORT       OffsetEprocessParentCID;
	USHORT       OffsetEprocessDirectoryTableBase;
	USHORT       SizePrcb;
	USHORT       OffsetPrcbDpcRoutine;
	USHORT       OffsetPrcbCurrentThread;
	USHORT       OffsetPrcbMhz;
	USHORT       OffsetPrcbCpuType;
	USHORT       OffsetPrcbVendorString;
	USHORT       OffsetPrcbProcStateContext;
	USHORT       OffsetPrcbNumber;
	USHORT       SizeEThread;
	ULONG64      KdPrintCircularBufferPtr;
	ULONG64      KdPrintBufferSize;
	ULONG64      KeLoaderBlock;
	USHORT       SizePcr;
	USHORT       OffsetPcrSelfPcr;
	USHORT       OffsetPcrCurrentPrcb;
	USHORT       OffsetPcrContainedPrcb;
	USHORT       OffsetPcrInitialBStore;
	USHORT       OffsetPcrBStoreLimit;
	USHORT       OffsetPcrInitialStack;
	USHORT       OffsetPcrStackLimit;
	USHORT       OffsetPrcbPcrPage;
	USHORT       OffsetPrcbProcStateSpecialReg;
	USHORT       GdtR0Code;
	USHORT       GdtR0Data;
	USHORT       GdtR0Pcr;
	USHORT       GdtR3Code;
	USHORT       GdtR3Data;
	USHORT       GdtR3Teb;
	USHORT       GdtLdt;
	USHORT       GdtTss;
	USHORT       Gdt64R3CmCode;
	USHORT       Gdt64R3CmTeb;
	ULONG64      IopNumTriageDumpDataBlocks;
	ULONG64      IopTriageDumpDataBlocks;
	ULONG64      VfCrashDataBlock;
	ULONG64      MmBadPagesDetected;
	ULONG64      MmZeroedPageSingleBitErrorsDetected;
	ULONG64      EtwpDebuggerData;
	USHORT       OffsetPrcbContext;
	USHORT       OffsetPrcbMaxBreakpoints;
	USHORT       OffsetPrcbMaxWatchpoints;
	ULONG        OffsetKThreadStackLimit;
	ULONG        OffsetKThreadStackBase;
	ULONG        OffsetKThreadQueueListEntry;
	ULONG        OffsetEThreadIrpList;
	USHORT       OffsetPrcbIdleThread;
	USHORT       OffsetPrcbNormalDpcState;
	USHORT       OffsetPrcbDpcStack;
	USHORT       OffsetPrcbIsrStack;
	USHORT       SizeKDPC_STACK_FRAME;
	USHORT       OffsetKPriQueueThreadListHead;
	USHORT       OffsetKThreadWaitReason;
	USHORT       Padding;
	ULONG64      PteBase;
	ULONG64      RetpolineStubFunctionTable;
	ULONG        RetpolineStubFunctionTableSize;
	ULONG        RetpolineStubOffset;
	ULONG        RetpolineStubSize;
} MY_KDDEBUGGER_DATA64;
#pragma pack(pop)

#define KDDEBUGGER_DATA_OFFSET  0x2080

const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4,
	{ 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

constexpr ULONG kSyscallHookId       = 0xF33;
constexpr ULONG kHalPmcCounterIdx    = 73;
constexpr ULONG kMaxEtwHooks         = 256;

constexpr ULONG kEtwMagic1Values[] = { 0x501802, 0x601802 };
constexpr USHORT kEtwMagic2 = 0xF33;

typedef struct _ETW_HOOK_ENTRY {
	PVOID OrigFunc;
	PVOID DetourFunc;
} ETW_HOOK_ENTRY;

static ULONG         G_EtwHookInit = 0;          
static ULONG_PTR*    G_EtwHalDispatchTable = NULL;
static PVOID         G_EtwOrigHalCollectPmc = NULL;
static BOOLEAN        G_EtwDispatchHookEnabled = FALSE;
static PVOID         G_EtwNtBase = NULL;
static ULONG         G_EtwNtSize = 0;
static ULONG_PTR     G_EtwKiServiceRepeat = 0;
static ETW_HOOK_ENTRY G_EtwHooks[kMaxEtwHooks] = {};
static ULONG         G_EtwHookCount = 0;
static KSPIN_LOCK    G_EtwHookLock;

static PVOID
EtwFindKernelBase(
	_Out_opt_ PULONG OutSize
)
{
	if (OutSize) *OutSize = 0;

	UNICODE_STRING FuncName;
	RtlInitUnicodeString(&FuncName, L"NtOpenProcess");
	PVOID FuncAddr = MmGetSystemRoutineAddress(&FuncName);
	if (!FuncAddr) return NULL;

	ULONG_PTR Addr = reinterpret_cast<ULONG_PTR>(FuncAddr) & ~static_cast<ULONG_PTR>(PAGE_SIZE - 1);

	while (Addr >= 0xFFFFF80000000000ULL)
	{
		__try
		{
			if (*reinterpret_cast<PUSHORT>(Addr) == IMAGE_DOS_SIGNATURE)
			{
				PIMAGE_DOS_HEADER Dos = reinterpret_cast<PIMAGE_DOS_HEADER>(Addr);
				if (Dos->e_lfanew > 0 && static_cast<ULONG>(Dos->e_lfanew) < PAGE_SIZE * 16)
				{
					PIMAGE_NT_HEADERS64 Nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
						Addr + Dos->e_lfanew);
					if (Nt->Signature == IMAGE_NT_SIGNATURE)
					{
						if (OutSize)
							*OutSize = Nt->OptionalHeader.SizeOfImage;
						return reinterpret_cast<PVOID>(Addr);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}
		Addr -= PAGE_SIZE;
	}

	return NULL;
}

static NTSTATUS EtwStartSyscallTrace(VOID);
static NTSTATUS EtwEndSyscallTrace(VOID);
static NTSTATUS EtwOpenPmcCounter(VOID);
static PVOID   EtwLocateEtwpMaxPmcCounter(VOID);
static VOID    EtwStackTraceToSyscall(VOID);
static VOID    EtwRecordSyscall(PVOID* CallRoutine);
static PVOID   EtwFindModuleBase(PCWSTR Name, PULONG Size);
static PVOID   EtwPatternScan(PVOID Base, ULONG Size, PCCH Pattern, PCCH Mask);
static PVOID   EtwPatternScanSection(PVOID Base, PCCH Pattern, PCCH Mask,
                                     PCCH SectionName);
static BOOLEAN EtwPatternCheck(PUCHAR Data, PCCH Pattern, PCCH Mask);

extern "C" {
	NTSYSCALLAPI NTSTATUS NTAPI ZwTraceControl(
		ULONG  FunctionCode, PVOID  InBuffer,  ULONG  InBufferLen,
		PVOID  OutBuffer,   ULONG  OutBufferLen, PULONG ReturnLength);

	NTSYSCALLAPI NTSTATUS NTAPI ZwSetSystemInformation(
		ULONG InfoClass, PVOID Buf, ULONG Length);
}

static BOOLEAN
EtwPatternCheck(
	PUCHAR Data,
	PCCH   Pattern,
	PCCH   Mask
)
{
	SIZE_T Len = strlen(Mask);
	for (SIZE_T i = 0; i < Len; i++)
	{
		if (Mask[i] == '?') continue;
		if (Data[i] != (UCHAR)Pattern[i]) return FALSE;
	}
	return TRUE;
}

static PVOID
EtwPatternScan(
	PVOID  Base,
	ULONG  Size,
	PCCH   Pattern,
	PCCH   Mask
)
{
	ULONG PatLen = (ULONG)strlen(Mask);
	if (PatLen > Size) return NULL;

	PUCHAR Scan = static_cast<PUCHAR>(Base);
	ULONG  Limit = Size - PatLen;

	for (ULONG i = 0; i < Limit; i++)
	{
		if (EtwPatternCheck(Scan + i, Pattern, Mask))
			return Scan + i;
	}
	return NULL;
}

static PVOID
EtwPatternScanSection(
	PVOID  Base,
	PCCH   Pattern,
	PCCH   Mask,
	PCCH   SectionName
)
{
	PIMAGE_DOS_HEADER Dos = static_cast<PIMAGE_DOS_HEADER>(Base);
	if (!MmIsAddressValid(Dos) || Dos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS Nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<PUCHAR>(Base) + Dos->e_lfanew);
	if (Nt->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
	for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++)
	{
		if (strstr(reinterpret_cast<PCCH>(Sec[i].Name), SectionName))
		{
			PVOID Result = EtwPatternScan(
				reinterpret_cast<PUCHAR>(Base) + Sec[i].VirtualAddress,
				Sec[i].Misc.VirtualSize, Pattern, Mask);
			if (Result) return Result;
		}
	}
	return NULL;
}

static PVOID
EtwFindModuleBase(
	PCWSTR  Name,
	PULONG  OutSize
)
{
	if (OutSize) *OutSize = 0;

	ULONG NeedSize = 0;
	ZwQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11),
		NULL, 0, &NeedSize);
	if (NeedSize == 0) return NULL;

	NeedSize += PAGE_SIZE;
	PVOID Buf = AllocPoolZero(NeedSize);
	if (!Buf) return NULL;

	NTSTATUS Status = ZwQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(11), Buf, NeedSize, &NeedSize);
	if (!NT_SUCCESS(Status)) { ExFreePoolWithTag(Buf, POOL_TAG); return NULL; }

	PVOID Found = NULL;
	ULONG Count = *(PULONG)Buf;
	PUCHAR Ptr = reinterpret_cast<PUCHAR>(Buf) + sizeof(ULONG);

	for (ULONG i = 0; i < Count; i++)
	{
		PVOID  ModBase  = *(PVOID*)(Ptr + 0x10);
		ULONG  ModSize  = *(PULONG)(Ptr + 0x18);
		PCCH   ModPath  = reinterpret_cast<PCCH>(Ptr + 0x28);

		PCCH FileName = strrchr(ModPath, '\\');
		if (!FileName) FileName = ModPath;
		else FileName++;

		BOOLEAN Match = FALSE;
		{
			const CHAR* a = FileName;
			const CHAR* b = "ntoskrnl.exe";
			SIZE_T n = 0;
			while (n < 13 && a[n] && b[n])
			{
				CHAR ca = (a[n] >= 'a' && a[n] <= 'z') ? (a[n] - 32) : a[n];
				CHAR cb = (b[n] >= 'a' && b[n] <= 'z') ? (b[n] - 32) : b[n];
				if (ca != cb) break;
				n++;
			}
			Match = (n == 13) || (a[n] == '\0' && b[n] == '\0');
		}

		if (Match)
		{
			
			if (Name == NULL ||
				(wcsstr(Name, L"ntoskrnl") || wcsstr(Name, L"ntkrnlmp")))
			{
				Found = ModBase;
				if (OutSize) *OutSize = ModSize;
			}
		}

		if (Name && Found == NULL)
		{
			ANSI_STRING AnsiName;
			UNICODE_STRING UcMod;
			RtlInitAnsiString(&AnsiName, FileName);
			if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&UcMod, &AnsiName, TRUE)))
			{
				if (_wcsnicmp(UcMod.Buffer, Name,
					min(UcMod.Length / 2, (ULONG)wcslen(Name))) == 0)
				{
					Found = ModBase;
					if (OutSize) *OutSize = ModSize;
				}
				RtlFreeUnicodeString(&UcMod);
			}
		}

		Ptr += 0x128; 
	}

	ExFreePoolWithTag(Buf, POOL_TAG);
	return Found;
}

static PVOID
EtwLocateEtwpMaxPmcCounter(VOID)
{

	static const PCCH sPattern =
		"\x44\x3b\x05\x00\x00\x00\x00\x0f\x87\x00\x00\x00\x00\x83\xb9"
		"\x00\x00\x00\x00\x01\x0f\x84\x00\x00\x00\x00\x48\x83\xb9"
		"\x00\x00\x00\x00\x00\x75\x00";
	static const PCCH sMask =
		"xxx????xx????xx????xxx????xxx????xx?";

	PUCHAR Match = static_cast<PUCHAR>(
		EtwPatternScanSection(G_EtwNtBase, sPattern, sMask, "PAGE"));
	if (!Match) return NULL;

	LONG Disp = *(PLONG)(Match + 3);
	return Match + 7 + Disp;
}

static ULONG
EtwGetLoggerId(VOID)
{
	ULONG LoggerId = 0;

	UNICODE_STRING FuncName;
	RtlInitUnicodeString(&FuncName, L"KeCapturePersistentThreadState");

	auto FuncPtr = reinterpret_cast<VOID(*)(PCONTEXT, ULONG, ULONG, ULONG,
		ULONG, ULONG, ULONG, PVOID)>(
		MmGetSystemRoutineAddress(&FuncName));

	if (!FuncPtr) return 0;

	PVOID DumpBlock = AllocPoolZero(0x40000);
	if (!DumpBlock) return 0;

	CONTEXT Ctx = {};
	Ctx.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&Ctx);

	FuncPtr(&Ctx, 0, 0, 0, 0, 0, 0, DumpBlock);

	MY_KDDEBUGGER_DATA64* KdData = reinterpret_cast<MY_KDDEBUGGER_DATA64*>(
		reinterpret_cast<PUCHAR>(DumpBlock) + KDDEBUGGER_DATA_OFFSET);

	ULONG_PTR EtwpData = static_cast<ULONG_PTR>(KdData->EtwpDebuggerData);
	if (EtwpData && MmIsAddressValid(reinterpret_cast<PVOID>(EtwpData)))
	{
		PULONG_PTR Ptr1 = *reinterpret_cast<PULONG_PTR*>(EtwpData + 0x10);
		if (Ptr1 && MmIsAddressValid(Ptr1))
		{
			PULONG_PTR Ptr2 = *reinterpret_cast<PULONG_PTR*>(
				reinterpret_cast<ULONG_PTR>(Ptr1) + 0x10);
			if (Ptr2 && MmIsAddressValid(Ptr2))
			{
				LoggerId = static_cast<ULONG>(Ptr2[0]);
			}
		}
	}

	ExFreePoolWithTag(DumpBlock, POOL_TAG);
	return LoggerId;
}

static NTSTATUS
EtwStartSyscallTrace(VOID)
{
	PMY_ETW_TRACE_PROPERTIES Prop = static_cast<PMY_ETW_TRACE_PROPERTIES>(
		AllocPoolZero(PAGE_SIZE));
	if (!Prop) return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(Prop, PAGE_SIZE);
	Prop->WnodeBufferSize    = PAGE_SIZE;
	Prop->WnodeFlags         = WNODE_FLAG_TRACED_GUID;
	Prop->WnodeGuid          = CkclSessionGuid;
	Prop->WnodeClientContext = 1;
	Prop->BufferSize         = sizeof(ULONG);
	Prop->MinimumBuffers     = 2;
	Prop->MaximumBuffers     = 2;
	Prop->LogFileMode        = EVENT_TRACE_BUFFERING_MODE;

	ULONG RetLen = 0;
	NTSTATUS Status = ZwTraceControl(EtwpStartTrace,
		Prop, PAGE_SIZE, Prop, PAGE_SIZE, &RetLen);

	if (Status == STATUS_OBJECT_NAME_COLLISION)
		Status = STATUS_SUCCESS;

	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] StartTrace failed: 0x%08X.\n", Status);
		ExFreePoolWithTag(Prop, POOL_TAG);
		return Status;
	}

	Prop->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
	Status = ZwTraceControl(EtwpUpdateTrace,
		Prop, PAGE_SIZE, Prop, PAGE_SIZE, &RetLen);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] Enable syscall trace failed: 0x%08X.\n", Status);
		EtwEndSyscallTrace();
	}

	ExFreePoolWithTag(Prop, POOL_TAG);
	return Status;
}

static NTSTATUS
EtwEndSyscallTrace(VOID)
{
	PMY_ETW_TRACE_PROPERTIES Prop = static_cast<PMY_ETW_TRACE_PROPERTIES>(
		AllocPoolZero(PAGE_SIZE));
	if (!Prop) return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(Prop, PAGE_SIZE);
	Prop->WnodeBufferSize    = PAGE_SIZE;
	Prop->WnodeFlags         = WNODE_FLAG_TRACED_GUID;
	Prop->WnodeGuid          = CkclSessionGuid;
	Prop->WnodeClientContext = 1;
	Prop->LogFileMode        = EVENT_TRACE_BUFFERING_MODE;

	ULONG RetLen = 0;
	NTSTATUS Status = ZwTraceControl(EtwpStopTrace,
		Prop, PAGE_SIZE, Prop, PAGE_SIZE, &RetLen);

	ExFreePoolWithTag(Prop, POOL_TAG);
	return Status;
}

static NTSTATUS
EtwOpenPmcCounter(VOID)
{
	ULONG LoggerId = EtwGetLoggerId();
	if (LoggerId == 0)
	{
		LogMessage("[ETWHook] Failed to get ETW logger ID.\n");
		return STATUS_NOT_FOUND;
	}

	MY_PROFILE_COUNTER_INFO* PmcInfo =
		static_cast<MY_PROFILE_COUNTER_INFO*>(
			AllocPoolZero(sizeof(MY_PROFILE_COUNTER_INFO)));
	if (!PmcInfo) return STATUS_INSUFFICIENT_RESOURCES;

	PmcInfo->InfoClass = MyEtwiProfileCounterList;
	PmcInfo->TraceHandle = ULongToHandle(LoggerId);
	PmcInfo->ProfileSource[0] = 1;

	NTSTATUS Status = ZwSetSystemInformation(
		SystemPerformanceTraceInformation,
		PmcInfo, sizeof(*PmcInfo));

	ExFreePoolWithTag(PmcInfo, POOL_TAG);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] PMC counter config failed: 0x%08X.\n", Status);
		return Status;
	}

	MY_SYSTEM_EVENT_INFO* EvtInfo =
		static_cast<MY_SYSTEM_EVENT_INFO*>(
			AllocPoolZero(sizeof(MY_SYSTEM_EVENT_INFO)));
	if (!EvtInfo) return STATUS_INSUFFICIENT_RESOURCES;

	EvtInfo->InfoClass = MyEtwiProfileEventList;
	EvtInfo->TraceHandle = ULongToHandle(LoggerId);
	EvtInfo->HookId[0] = kSyscallHookId;

	Status = ZwSetSystemInformation(
		SystemPerformanceTraceInformation,
		EvtInfo, sizeof(*EvtInfo));

	ExFreePoolWithTag(EvtInfo, POOL_TAG);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] PMC event config failed: 0x%08X.\n", Status);
		return Status;
	}

	LogMessage("[ETWHook] PMC counter + syscall event configured.\n");
	return STATUS_SUCCESS;
}

NTSTATUS
EtwSyscallAddHook(
	_In_ PVOID OrigSyscall,
	_In_ PVOID DetourFunc
)
{
	if (!OrigSyscall || !DetourFunc)
		return STATUS_INVALID_PARAMETER;

	KIRQL Irql;
	KeAcquireSpinLock(&G_EtwHookLock, &Irql);

	if (G_EtwHookCount >= kMaxEtwHooks)
	{
		KeReleaseSpinLock(&G_EtwHookLock, Irql);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	G_EtwHooks[G_EtwHookCount].OrigFunc   = OrigSyscall;
	G_EtwHooks[G_EtwHookCount].DetourFunc = DetourFunc;
	G_EtwHookCount++;

	KeReleaseSpinLock(&G_EtwHookLock, Irql);

	LogMessage("[ETWHook] Hook #%u added: %p -> %p.\n",
		G_EtwHookCount - 1, OrigSyscall, DetourFunc);
	return STATUS_SUCCESS;
}

static VOID
EtwRecordSyscall(
	_Inout_ PVOID* CallRoutine
)
{
	if (!G_EtwDispatchHookEnabled || CallRoutine == NULL)
		return;
	
	PVOID SyscallAddr = CallRoutine[9];

	KIRQL Irql;
	KeAcquireSpinLock(&G_EtwHookLock, &Irql);

	for (ULONG i = 0; i < G_EtwHookCount; i++)
	{
		if (G_EtwHooks[i].OrigFunc == SyscallAddr &&
			G_EtwHooks[i].DetourFunc != NULL)
		{
			CallRoutine[9] = G_EtwHooks[i].DetourFunc;
			break;
		}
	}

	KeReleaseSpinLock(&G_EtwHookLock, Irql);
}

static VOID
EtwStackTraceToSyscall(VOID)
{
	
	if (ExGetPreviousMode() == KernelMode)
		return;

	if (!G_EtwKiServiceRepeat || !G_EtwNtBase)
		return;

	PVOID* StackMax   = reinterpret_cast<PVOID*>(__readgsqword(0x1A8));
	PVOID* StackFrame = reinterpret_cast<PVOID*>(_AddressOfReturnAddress());
	PVOID* CurStack   = StackFrame;

	for (; CurStack < StackMax; CurStack++)
	{
		PUSHORT AsShort = reinterpret_cast<PUSHORT>(CurStack);
		if (*AsShort != kEtwMagic2) continue;

		CurStack++;
		PULONG AsUlong = reinterpret_cast<PULONG>(CurStack);
		if (*AsUlong != kEtwMagic1Values[0] && *AsUlong != kEtwMagic1Values[1])
			continue;

		for (; CurStack < StackMax; CurStack++)
		{
			ULONG_PTR Val = reinterpret_cast<ULONG_PTR>(*CurStack);
			ULONG_PTR KiSvcBase = reinterpret_cast<ULONG_PTR>(
				PAGE_ALIGN(G_EtwKiServiceRepeat));
			if (Val >= KiSvcBase &&
				Val <= (KiSvcBase + PAGE_SIZE * 8))
			{
				EtwRecordSyscall(CurStack);
				break;
			}
		}
		break;
	}
}

static VOID
hk_HalCollectPmcCounters(
	_In_ PVOID   Ctx,
	_In_ ULONG64 TraceBufferEnd
)
{
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
		EtwStackTraceToSyscall();

	auto Orig = reinterpret_cast<VOID(*)(PVOID, ULONG64)>(
		G_EtwOrigHalCollectPmc);
	Orig(Ctx, TraceBufferEnd);
}

NTSTATUS
EtwSyscallHookInit(VOID)
{
	
	ULONG_PTR KiSystemCall64 = static_cast<ULONG_PTR>(__readmsr(0xC0000082));
	if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&G_EtwHookInit),
		1, 0) != 0)
		return STATUS_ALREADY_REGISTERED;

	KeInitializeSpinLock(&G_EtwHookLock);

	G_EtwNtBase = EtwFindKernelBase(&G_EtwNtSize);
	if (!G_EtwNtBase)
	{
		ULONG_PTR NtBase = 0;
		ULONG     NtSize = 0;
		if (GetNtoskrnlInfo(&NtBase, &NtSize) && NtBase != 0)
		{
			G_EtwNtBase = reinterpret_cast<PVOID>(NtBase);
			G_EtwNtSize = NtSize;
		}
	}
	if (!G_EtwNtBase)
	{
		G_EtwNtBase = EtwFindModuleBase(L"ntoskrnl.exe", &G_EtwNtSize);
	}
	if (!G_EtwNtBase)
	{
		LogMessage("[ETWHook] Cannot find ntoskrnl.exe base.\n");
		G_EtwHookInit = 0;
		return STATUS_NOT_FOUND;
	}

	G_EtwKiServiceRepeat = 0;
	if (KiSystemCall64)
	{

		PUCHAR p = reinterpret_cast<PUCHAR>(KiSystemCall64);
		PUCHAR end = p + PAGE_SIZE;

		BOOLEAN SawSwapgs = FALSE;
		while (p < (end - 2))
		{
			if (p[0] == 0x0F && p[1] == 0x01 && p[2] == 0xF8)
			{
				SawSwapgs = TRUE;
				p += 3;
				break;
			}
			p++;
		}

		if (SawSwapgs)
		{
			
			while (p < (end - 1))
			{
				if (*p == 0xFA)
				{
					G_EtwKiServiceRepeat = reinterpret_cast<ULONG_PTR>(p);
					break;
				}
				p++;
			}
		}

		if (!G_EtwKiServiceRepeat)
		{
			
			G_EtwKiServiceRepeat = KiSystemCall64;
		}
	}

	if (!G_EtwKiServiceRepeat)
	{
		LogMessage("[ETWHook] Cannot locate KiSystemServiceRepeat.\n");
		G_EtwHookInit = 0;
		return STATUS_NOT_FOUND;
	}

	LogMessage("[ETWHook] ntoskrnl @ %p, KiSystemCall64/Repeat @ %p.\n",
		G_EtwNtBase, reinterpret_cast<PVOID>(G_EtwKiServiceRepeat));

	NTSTATUS Status = EtwStartSyscallTrace();
	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] Cannot start syscall trace: 0x%08X.\n", Status);
		InterlockedExchange(reinterpret_cast<LONG*>(&G_EtwHookInit), 0);
		return Status;
	}

	Status = EtwOpenPmcCounter();
	if (!NT_SUCCESS(Status))
	{
		LogMessage("[ETWHook] Cannot open PMC counter: 0x%08X.\n", Status);
		EtwEndSyscallTrace();
		G_EtwHookInit = 0;
		return Status;
	}

	G_EtwDispatchHookEnabled = FALSE;
	G_EtwHookInit = 2;
	LogMessage("[ETWHook] ETW syscall telemetry initialized; kernel dispatch detour disabled (PatchGuard-safe mode).\n");

	return STATUS_SUCCESS;
}

VOID
EtwSyscallHookCleanup(VOID)
{
	ULONG State = InterlockedExchange(reinterpret_cast<LONG*>(&G_EtwHookInit), 3);
	if (State == 0) return;

	LogMessage("[ETWHook] Cleaning up...\n");

	LARGE_INTEGER Delay;
	Delay.QuadPart = -2000000; 
	KeDelayExecutionThread(KernelMode, FALSE, &Delay);

	EtwEndSyscallTrace();

	KIRQL Irql;
	KeAcquireSpinLock(&G_EtwHookLock, &Irql);
	RtlZeroMemory(G_EtwHooks, sizeof(G_EtwHooks));
	G_EtwHookCount = 0;
	KeReleaseSpinLock(&G_EtwHookLock, Irql);
	G_EtwDispatchHookEnabled = FALSE;

	G_EtwHalDispatchTable = NULL;
	G_EtwOrigHalCollectPmc = NULL;
	G_EtwKiServiceRepeat = 0;
	G_EtwNtBase = NULL;
	G_EtwNtSize = 0;
	InterlockedExchange(reinterpret_cast<LONG*>(&G_EtwHookInit), 0);

	LogMessage("[ETWHook] Cleanup complete.\n");
}

static VOID
EtwRegisterUserHooks(VOID)
{

}

NTSTATUS
EtwHookInstall(VOID)
{
	NTSTATUS Status = EtwSyscallHookInit();
	if (!NT_SUCCESS(Status))
		return Status;

	EtwRegisterUserHooks();

	return STATUS_SUCCESS;
}

VOID
EtwHookRemove(VOID)
{
	EtwSyscallHookCleanup();
}
