
#ifdef _M_AMD64

#ifndef KI_USER_SHARED_DATA
#define KI_USER_SHARED_DATA 0xFFFFF78000000000ULL
#endif

#define MAX_SCAN_BYTES  4096
#define SSDT_TABLE_SCAN 65536

static BOOLEAN
GetNtoskrnlInfo(
	_Out_ PULONG_PTR Base,
	_Out_ PULONG Size
)
{
	PMY_MODULE_INFO ModuleInfo = GetSystemModuleInfo();
	if (ModuleInfo == NULL)
		return FALSE;

	BOOLEAN Found = FALSE;

	for (ULONG i = 0; i < ModuleInfo->ModulesCount; i++)
	{
		PCHAR Name = reinterpret_cast<PCHAR>(
			ModuleInfo->Modules[i].FullPathName +
			ModuleInfo->Modules[i].OffsetToFileName);

		if (_strnicmp(Name, "ntoskrnl.exe", 12) == 0 ||
			_strnicmp(Name, "ntkrnlmp.exe", 12) == 0)
		{
			*Base = reinterpret_cast<ULONG_PTR>(ModuleInfo->Modules[i].ImageBase);
			*Size = ModuleInfo->Modules[i].ImageSize;
			Found = TRUE;
			break;
		}
	}

	ExFreePoolWithTag(ModuleInfo, POOL_TAG);
	return Found;
}

static BOOLEAN
GetModuleBase(
	_In_ PCSTR ModuleName,
	_Out_ PULONG_PTR Base,
	_Out_opt_ PULONG Size
)
{
	PMY_MODULE_INFO ModuleInfo = GetSystemModuleInfo();
	if (ModuleInfo == NULL)
		return FALSE;

	BOOLEAN Found = FALSE;
	SIZE_T NameLen = strlen(ModuleName);

	for (ULONG i = 0; i < ModuleInfo->ModulesCount; i++)
	{
		PCHAR Name = reinterpret_cast<PCHAR>(
			ModuleInfo->Modules[i].FullPathName +
			ModuleInfo->Modules[i].OffsetToFileName);

		if (_strnicmp(Name, ModuleName, NameLen) == 0)
		{
			*Base = reinterpret_cast<ULONG_PTR>(ModuleInfo->Modules[i].ImageBase);
			if (Size)
				*Size = ModuleInfo->Modules[i].ImageSize;
			Found = TRUE;
			break;
		}
	}

	ExFreePoolWithTag(ModuleInfo, POOL_TAG);
	return Found;
}

static BOOLEAN
ExtractLeaRipDisp(
	_In_ PUCHAR Start,
	_In_ SIZE_T NumBytes,
	_In_ UCHAR Opcode0,
	_In_ UCHAR Opcode1,
	_In_ UCHAR Opcode2,
	_Out_ PULONG_PTR Result
)
{
	for (SIZE_T i = 0; i + 6 < NumBytes; i++)
	{
		if (Start[i] == Opcode0 &&
			Start[i + 1] == Opcode1 &&
			Start[i + 2] == Opcode2)
		{
			LONG Disp = *reinterpret_cast<PLONG>(Start + i + 3);
			*Result = reinterpret_cast<ULONG_PTR>(Start + i + 7) + Disp;
			return TRUE;
		}
	}

	return FALSE;
}

typedef struct _SERVICE_TARGET_RANGE {
	ULONG_PTR Base;
	ULONG     Size;
} SERVICE_TARGET_RANGE, * PSERVICE_TARGET_RANGE;

static BOOLEAN
AddressInServiceRanges(
	_In_ ULONG_PTR Address,
	_In_reads_(RangeCount) const SERVICE_TARGET_RANGE* Ranges,
	_In_ ULONG RangeCount
)
{
	for (ULONG i = 0; i < RangeCount; ++i)
	{
		if (Ranges[i].Base != 0 &&
			Ranges[i].Size != 0 &&
			Address >= Ranges[i].Base &&
			Address < Ranges[i].Base + Ranges[i].Size)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static ULONG
CountEncodedServiceTable(
	_In_ ULONG_PTR TableBase,
	_In_ ULONG_PTR ScanEnd,
	_In_reads_(RangeCount) const SERVICE_TARGET_RANGE* Ranges,
	_In_ ULONG RangeCount,
	_In_ ULONG MaxEntries
)
{
	ULONG Count = 0;
	PLONG Table = reinterpret_cast<PLONG>(TableBase);

	for (ULONG i = 0; i < MaxEntries; ++i)
	{
		if (TableBase + ((ULONG_PTR)i + 1) * sizeof(LONG) > ScanEnd)
			break;

		LONG Encoded;
		__try
		{
			Encoded = *(volatile LONG*)&Table[i];
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}
		if (Encoded == 0)
			break;

		const ULONG_PTR FunctionAddress = TableBase + (Encoded >> 4);
		__try
		{
			if (!AddressInServiceRanges(FunctionAddress, Ranges, RangeCount))
				break;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		++Count;
	}

	return Count;
}

static BOOLEAN
FindEncodedServiceTableInRange(
	_In_ ULONG_PTR ScanBase,
	_In_ ULONG ScanSize,
	_In_reads_(RangeCount) const SERVICE_TARGET_RANGE* Ranges,
	_In_ ULONG RangeCount,
	_In_ ULONG MinEntries,
	_In_ ULONG MaxEntries,
	_Out_ PULONG_PTR TableBase,
	_Out_ PULONG TableCount
)
{
	*TableBase = 0;
	*TableCount = 0;

	if (ScanBase == 0 || ScanSize < sizeof(LONG) * MinEntries)
		return FALSE;

	const ULONG_PTR ScanEnd = ScanBase + ScanSize;

	for (ULONG_PTR Candidate = ScanBase;
		Candidate + sizeof(LONG) * MinEntries <= ScanEnd;
		Candidate += sizeof(LONG))
	{
		const ULONG Count = CountEncodedServiceTable(
			Candidate, ScanEnd, Ranges, RangeCount, MaxEntries);

		if (Count >= MinEntries && Count > *TableCount)
		{
			*TableBase = Candidate;
			*TableCount = Count;
		}
	}

	return *TableBase != 0;
}

typedef struct _IMAGE_SECTION_RANGE {
	ULONG_PTR Base;
	ULONG     Size;
} IMAGE_SECTION_RANGE, * PIMAGE_SECTION_RANGE;

typedef struct _RTL_BALANCED_LINKS_LOCAL {
	struct _RTL_BALANCED_LINKS_LOCAL* Parent;
	struct _RTL_BALANCED_LINKS_LOCAL* LeftChild;
	struct _RTL_BALANCED_LINKS_LOCAL* RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS_LOCAL, * PRTL_BALANCED_LINKS_LOCAL;

typedef struct _RTL_AVL_TABLE_LOCAL {
	RTL_BALANCED_LINKS_LOCAL BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PVOID RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine;
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE_LOCAL, * PRTL_AVL_TABLE_LOCAL;

typedef struct _PIDDB_CACHE_ENTRY_LOCAL {
	LIST_ENTRY List;
	UNICODE_STRING DriverName;
	ULONG TimeDateStamp;
	NTSTATUS LoadStatus;
	CHAR Padding[16];
} PIDDB_CACHE_ENTRY_LOCAL, * PPIDDB_CACHE_ENTRY_LOCAL;

extern "C" NTSYSAPI PVOID NTAPI RtlEnumerateGenericTableWithoutSplayingAvl(
	_In_ PRTL_AVL_TABLE Table,
	_Inout_ PVOID* RestartKey
);

static ULONG
CollectWritableImageSections(
	_In_ ULONG_PTR ImageBase,
	_Out_writes_(MaxRanges) PIMAGE_SECTION_RANGE Ranges,
	_In_ ULONG MaxRanges
)
{
	if (ImageBase == 0 || Ranges == NULL || MaxRanges == 0)
		return 0;

	auto Dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
	if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	auto Nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(ImageBase + Dos->e_lfanew);
	if (Nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	ULONG Count = 0;
	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (USHORT Index = 0; Index < Nt->FileHeader.NumberOfSections && Count < MaxRanges; ++Index, ++Section)
	{
		if ((Section->Characteristics & IMAGE_SCN_MEM_WRITE) == 0)
			continue;
		if (Section->VirtualAddress == 0 || Section->Misc.VirtualSize == 0)
			continue;

		Ranges[Count].Base = ImageBase + Section->VirtualAddress;
		Ranges[Count].Size = Section->Misc.VirtualSize;
		++Count;
	}

	return Count;
}

static BOOLEAN
AddressInImageSections(
	_In_ ULONG_PTR Address,
	_In_reads_(RangeCount) const IMAGE_SECTION_RANGE* Ranges,
	_In_ ULONG RangeCount
)
{
	for (ULONG Index = 0; Index < RangeCount; ++Index)
	{
		if (Address >= Ranges[Index].Base &&
			Address < Ranges[Index].Base + Ranges[Index].Size)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static BOOLEAN
LooksLikeKernelPointer(
	_In_ ULONG_PTR Address
)
{
#ifdef _WIN64
	return Address == 0 || Address >= 0xFFFF000000000000ULL;
#else
	return Address == 0 || Address >= 0x80000000UL;
#endif
}

static ULONG
ScorePiDdbCacheCandidate(
	_In_ ULONG_PTR Candidate,
	_In_ ULONG_PTR NtosBase,
	_In_ ULONG NtosSize
)
{
	if (Candidate == 0 || (Candidate & (sizeof(PVOID) - 1)) != 0)
		return 0;

	ULONG Score = 0;

	__try
	{
		auto* Table = reinterpret_cast<PRTL_AVL_TABLE_LOCAL>(Candidate);
		if (Table == NULL)
			return 0;

		if (Table->CompareRoutine != NULL &&
			reinterpret_cast<ULONG_PTR>(Table->CompareRoutine) >= NtosBase &&
			reinterpret_cast<ULONG_PTR>(Table->CompareRoutine) < NtosBase + NtosSize)
		{
			Score += 5;
		}
		else
		{
			return 0;
		}

		if (Table->AllocateRoutine != NULL &&
			reinterpret_cast<ULONG_PTR>(Table->AllocateRoutine) >= NtosBase &&
			reinterpret_cast<ULONG_PTR>(Table->AllocateRoutine) < NtosBase + NtosSize)
		{
			Score += 2;
		}

		if (Table->FreeRoutine != NULL &&
			reinterpret_cast<ULONG_PTR>(Table->FreeRoutine) >= NtosBase &&
			reinterpret_cast<ULONG_PTR>(Table->FreeRoutine) < NtosBase + NtosSize)
		{
			Score += 2;
		}

		if (Table->TableContext == NULL || LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->TableContext)))
			Score += 1;
		if (LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->OrderedPointer)))
			Score += 1;
		if (LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->RestartKey)))
			Score += 1;
		if (LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->BalancedRoot.Parent)) &&
			LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->BalancedRoot.LeftChild)) &&
			LooksLikeKernelPointer(reinterpret_cast<ULONG_PTR>(Table->BalancedRoot.RightChild)))
		{
			Score += 2;
		}

		if (Table->NumberGenericTableElements == 0)
		{
			Score += 1;
		}
		else if (Table->NumberGenericTableElements < 0x100000)
		{
			Score += 4;
		}
		else
		{
			return 0;
		}

		if (Table->DepthOfTree < 0x1000)
			Score += 1;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return Score;
}

static BOOLEAN
ExtractAnyLeaRipCandidate(
	_In_ PUCHAR Start,
	_In_ SIZE_T NumBytes,
	_In_ ULONG_PTR NtosBase,
	_In_ ULONG NtosSize,
	_In_reads_(WritableCount) const IMAGE_SECTION_RANGE* WritableRanges,
	_In_ ULONG WritableCount,
	_Out_ PULONG_PTR Result
)
{
	static const UCHAR Patterns[][3] = {
		{ 0x48, 0x8D, 0x0D }, { 0x48, 0x8D, 0x15 }, { 0x48, 0x8D, 0x1D },
		{ 0x4C, 0x8D, 0x05 }, { 0x4C, 0x8D, 0x0D }, { 0x4C, 0x8D, 0x15 },
		{ 0x4C, 0x8D, 0x1D }, { 0x4C, 0x8D, 0x25 }
	};

	for (SIZE_T Offset = 0; Offset + 7 <= NumBytes; ++Offset)
	{
		for (ULONG PatternIndex = 0; PatternIndex < RTL_NUMBER_OF(Patterns); ++PatternIndex)
		{
			if (Start[Offset] != Patterns[PatternIndex][0] ||
				Start[Offset + 1] != Patterns[PatternIndex][1] ||
				Start[Offset + 2] != Patterns[PatternIndex][2])
			{
				continue;
			}

			LONG Disp = *reinterpret_cast<PLONG>(Start + Offset + 3);
			ULONG_PTR Candidate = reinterpret_cast<ULONG_PTR>(Start + Offset + 7) + Disp;
			if (Candidate < NtosBase || Candidate >= NtosBase + NtosSize)
				continue;
			if ((Candidate & (sizeof(PVOID) - 1)) != 0)
				continue;
			if (!AddressInImageSections(Candidate, WritableRanges, WritableCount))
				continue;

			*Result = Candidate;
			return TRUE;
		}
	}

	return FALSE;
}

static BOOLEAN
QuerySsdt(
	_In_ ULONG_PTR NtosBase,
	_In_ ULONG NtosSize,
	_Out_ PULONG_PTR SsdtBase,
	_Out_ PULONG SsdtCount,
	_Out_ PULONG_PTR SsdtArgTable
)
{
	*SsdtBase = 0;
	*SsdtCount = 0;
	*SsdtArgTable = 0;

	const SERVICE_TARGET_RANGE NtosRange = { NtosBase, NtosSize };
	ULONG64 Lstar = ReadMsrEmulate(0xC0000082);
	if (Lstar == 0 || Lstar < NtosBase ||
		Lstar >= NtosBase + NtosSize)
	{
		return FindEncodedServiceTableInRange(
			NtosBase,
			NtosSize,
			&NtosRange,
			1,
			64,
			SYSTEM_TABLE_MAX_ENTRIES,
			SsdtBase,
			SsdtCount);
	}

	PUCHAR ScanStart = reinterpret_cast<PUCHAR>(Lstar);
	SIZE_T ScanLen = MAX_SCAN_BYTES;

	ULONG_PTR ServiceTable = 0;
	if (ExtractLeaRipDisp(ScanStart, ScanLen,
		0x4C, 0x8D, 0x15, &ServiceTable) &&
		ServiceTable >= NtosBase &&
		ServiceTable < NtosBase + NtosSize)
	{
		const ULONG Count = CountEncodedServiceTable(
			ServiceTable,
			NtosBase + NtosSize,
			&NtosRange,
			1,
			SYSTEM_TABLE_MAX_ENTRIES);

		if (Count != 0)
		{
			ULONG_PTR ArgTable = 0;
			ExtractLeaRipDisp(ScanStart, ScanLen,
				0x4C, 0x8D, 0x1D, &ArgTable);

			*SsdtBase = ServiceTable;
			*SsdtCount = Count;
			if (ArgTable >= NtosBase && ArgTable < NtosBase + NtosSize)
				*SsdtArgTable = ArgTable;

			return TRUE;
		}
	}

	return FindEncodedServiceTableInRange(
		NtosBase,
		NtosSize,
		&NtosRange,
		1,
		64,
		SYSTEM_TABLE_MAX_ENTRIES,
		SsdtBase,
		SsdtCount);
}

static BOOLEAN
QueryShadowSsdt(
	_In_ ULONG_PTR NtosBase,
	_In_ ULONG NtosSize,
	_In_ ULONG_PTR SsdtBase,
	_Out_ PULONG_PTR ShadowBase,
	_Out_ PULONG ShadowCount,
	_Out_ PULONG_PTR ShadowArgTable
)
{
	*ShadowBase = 0;
	*ShadowCount = 0;
	*ShadowArgTable = 0;

	UNREFERENCED_PARAMETER(NtosBase);
	UNREFERENCED_PARAMETER(NtosSize);
	UNREFERENCED_PARAMETER(SsdtBase);

	SERVICE_TARGET_RANGE Win32kRanges[3] = { 0 };
	ULONG RangeCount = 0;

	GetModuleBase("win32k.sys",
		&Win32kRanges[RangeCount].Base,
		&Win32kRanges[RangeCount].Size);
	if (Win32kRanges[RangeCount].Base != 0)
		++RangeCount;

	GetModuleBase("win32kbase.sys",
		&Win32kRanges[RangeCount].Base,
		&Win32kRanges[RangeCount].Size);
	if (Win32kRanges[RangeCount].Base != 0)
		++RangeCount;

	GetModuleBase("win32kfull.sys",
		&Win32kRanges[RangeCount].Base,
		&Win32kRanges[RangeCount].Size);
	if (Win32kRanges[RangeCount].Base != 0)
		++RangeCount;

	if (RangeCount == 0)
		return FALSE;

	for (ULONG i = 0; i < RangeCount; ++i)
	{
		ULONG_PTR CandidateBase = 0;
		ULONG CandidateCount = 0;

		if (FindEncodedServiceTableInRange(
			Win32kRanges[i].Base,
			Win32kRanges[i].Size,
			Win32kRanges,
			RangeCount,
			64,
			SYSTEM_TABLE_MAX_ENTRIES,
			&CandidateBase,
			&CandidateCount) &&
			CandidateCount > *ShadowCount)
		{
			*ShadowBase = CandidateBase;
			*ShadowCount = CandidateCount;
		}
	}

	return *ShadowBase != 0;
}

static BOOLEAN
QueryPiDDBCache(
	_In_ ULONG_PTR NtosBase,
	_In_ ULONG NtosSize,
	_Out_ PULONG_PTR TableAddr
)
{
	*TableAddr = 0;
	ULONG_PTR BestCandidate = 0;
	ULONG BestScore = 0;

	IMAGE_SECTION_RANGE WritableRanges[16] = {};
	const ULONG WritableCount = CollectWritableImageSections(
		NtosBase, WritableRanges, RTL_NUMBER_OF(WritableRanges));
	if (WritableCount == 0)
		return FALSE;

	const PCWSTR AnchorNames[] = {
		L"SeValidateImageHeader",
		L"SeValidateImageData",
		L"CiValidateImageHeader",
		L"CiCheckSignedFile",
	};

	for (ULONG Index = 0; Index < RTL_NUMBER_OF(AnchorNames); ++Index)
	{
		UNICODE_STRING Fn;
		RtlInitUnicodeString(&Fn, AnchorNames[Index]);
		PVOID Addr = MmGetSystemRoutineAddress(&Fn);
		if (Addr == NULL)
			continue;

		ULONG_PTR Candidate = 0;
		if (ExtractAnyLeaRipCandidate(
			reinterpret_cast<PUCHAR>(Addr),
			MAX_SCAN_BYTES * 2,
			NtosBase,
			NtosSize,
			WritableRanges,
			WritableCount,
			&Candidate))
		{
			const ULONG Score = ScorePiDdbCacheCandidate(
				Candidate, NtosBase, NtosSize);
			if (Score > BestScore)
			{
				BestScore = Score;
				BestCandidate = Candidate;
			}
		}
	}

	if (BestCandidate != 0 && BestScore >= 8)
	{
		*TableAddr = BestCandidate;
		return TRUE;
	}

	return FALSE;
}

#endif 

NTSTATUS
QuerySystemTables(
	_Out_ PSYSTEM_TABLES_OUTPUT Output,
	_In_  ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;

	if (Output == NULL || OutputLength < sizeof(SYSTEM_TABLES_OUTPUT))
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Output, sizeof(SYSTEM_TABLES_OUTPUT));
	*BytesReturned = sizeof(SYSTEM_TABLES_OUTPUT);

#ifdef _M_AMD64

	{
		UCHAR Idtr[10];
		SidtEmulate(Idtr);
		Output->IdtLimit = *reinterpret_cast<PUSHORT>(Idtr);
		Output->IdtBase = *reinterpret_cast<PULONG_PTR>(Idtr + 2);
	}

	{
		UCHAR Gdtr[10];
		RtlZeroMemory(Gdtr, sizeof(Gdtr));
		SgdtEmulate(Gdtr);
		Output->GdtLimit = *reinterpret_cast<PUSHORT>(Gdtr);
		Output->GdtBase = *reinterpret_cast<PULONG_PTR>(Gdtr + 2);
	}

	{
		Output->KuserSharedData =
			static_cast<ULONG_PTR>(KI_USER_SHARED_DATA);
		KeQueryInterruptTime(
			reinterpret_cast<PLARGE_INTEGER>(&Output->InterruptTime));
		KeQuerySystemTime(
			reinterpret_cast<PLARGE_INTEGER>(&Output->SystemTime));

		Output->TickCount = *reinterpret_cast<volatile ULONG*>(
			static_cast<ULONG_PTR>(KI_USER_SHARED_DATA) + 0x320);
	}

	Output->Cr0 = __readcr0();
	Output->Cr2 = __readcr2();
	Output->Cr3 = __readcr3();
	Output->Cr4 = __readcr4();
	Output->MsrLstar = ReadMsrEmulate(0xC0000082);
	Output->MsrStar = ReadMsrEmulate(0xC0000081);
	Output->MsrFmask = ReadMsrEmulate(0xC0000084);
	Output->MsrEfer = ReadMsrEmulate(0xC0000080);

	ULONG NtosSize = 0;
	if (!GetNtoskrnlInfo(&Output->NtoskrnlBase, &NtosSize))
		Output->NtoskrnlBase = 0;
	Output->NtoskrnlSize = NtosSize;

	if (Output->NtoskrnlBase != 0)
	{
		QuerySsdt(Output->NtoskrnlBase, Output->NtoskrnlSize,
			&Output->SsdtBase, &Output->SsdtCount, &Output->SsdtArgTable);

		QueryShadowSsdt(Output->NtoskrnlBase, Output->NtoskrnlSize,
			Output->SsdtBase,
			&Output->ShadowSsdtBase,
			&Output->ShadowSsdtCount,
			&Output->ShadowSsdtArgTable);

		QueryPiDDBCache(Output->NtoskrnlBase, Output->NtoskrnlSize,
			&Output->PiDDBCacheTable);
	}

#else
	UNREFERENCED_PARAMETER(Output);
	UNREFERENCED_PARAMETER(OutputLength);
	*BytesReturned = 0;
	return STATUS_NOT_SUPPORTED;
#endif

	return STATUS_SUCCESS;
}

NTSTATUS
EnumerateSystemTableEntries(
	_In_ ULONG TableKind,
	_Out_ PSYSTEM_TABLE_ENTRIES_OUTPUT Output,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	SYSTEM_TABLES_OUTPUT Tables = { 0 };
	ULONG Ignored = 0;
	ULONG_PTR Base = 0;
	ULONG_PTR ArgumentTable = 0;
	ULONG TotalCount = 0;

	*BytesReturned = 0;
	if (Output == NULL || OutputLength < sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT) ||
		TableKind > SYSTEM_TABLE_KIND_GDT)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Output, sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT));
	Output->TableKind = TableKind;
	if (!NT_SUCCESS(QuerySystemTables(&Tables, sizeof(Tables), &Ignored)))
		return STATUS_UNSUCCESSFUL;

	switch (TableKind)
	{
	case SYSTEM_TABLE_KIND_IDT:
		Base = Tables.IdtBase;
		TotalCount = (Tables.IdtLimit + 1) / 16;
		break;
	case SYSTEM_TABLE_KIND_GDT:
		Base = Tables.GdtBase;
		TotalCount = (Tables.GdtLimit + 1) / 8;
		break;
	case SYSTEM_TABLE_KIND_IO_TIMER:
		Output->TableBase = Tables.KuserSharedData;
		Output->TotalCount = 4;
		Output->Count = 4;
		Output->Entries[0].Index = 0; Output->Entries[0].Address = Tables.KuserSharedData;
		Output->Entries[1].Index = 1; Output->Entries[1].Address = (ULONG_PTR)Tables.SystemTime;
		Output->Entries[2].Index = 2; Output->Entries[2].Address = (ULONG_PTR)Tables.InterruptTime;
		Output->Entries[3].Index = 3; Output->Entries[3].Address = Tables.TickCount;
		*BytesReturned = sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT);
		return STATUS_SUCCESS;
	case SYSTEM_TABLE_KIND_SSDT:
		Base = Tables.SsdtBase; ArgumentTable = Tables.SsdtArgTable; TotalCount = Tables.SsdtCount;
		break;
	case SYSTEM_TABLE_KIND_SHADOW_SSDT:
		Base = Tables.ShadowSsdtBase; ArgumentTable = Tables.ShadowSsdtArgTable; TotalCount = Tables.ShadowSsdtCount;
		break;
	}

	if (Base == 0 || TotalCount == 0)
		return STATUS_NOT_FOUND;

	Output->TableBase = Base;
	Output->TotalCount = TotalCount;
	Output->Count = min(TotalCount, (ULONG)SYSTEM_TABLE_MAX_ENTRIES);
	for (ULONG Index = 0; Index < Output->Count; ++Index)
	{
		SYSTEM_TABLE_ENTRY* Entry = &Output->Entries[Index];
		Entry->Index = Index;

		__try
		{
			if (TableKind == SYSTEM_TABLE_KIND_IDT)
			{
				const ULONG64 Low = *(volatile ULONG64*)(Base + Index * 16);
				const ULONG64 High = *(volatile ULONG64*)(Base + Index * 16 + 8);
				Entry->ArgumentBytes = (ULONG)((Low >> 16) & 0xFFFF);
				Entry->Address = (ULONG_PTR)((Low & 0xFFFF) | (((Low >> 48) & 0xFFFF) << 16) | ((High & 0xFFFFFFFF) << 32));
			}
			else if (TableKind == SYSTEM_TABLE_KIND_GDT)
			{
				Entry->Address = *(volatile ULONG64*)(Base + Index * 8);
			}
			else
			{
				const LONG Encoded = *(volatile LONG*)(Base + Index * sizeof(LONG));
				Entry->Address = Base + (Encoded >> 4);
				Entry->ArgumentBytes = ArgumentTable ? *(volatile UCHAR*)(ArgumentTable + Index) : 0;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}
	}

	*BytesReturned = sizeof(SYSTEM_TABLE_ENTRIES_OUTPUT);
	return STATUS_SUCCESS;
}

NTSTATUS
EnumeratePiDDBCache(
	_Out_ PPIDDB_CACHE_ENUM_OUTPUT Output,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	SYSTEM_TABLES_OUTPUT Tables = { 0 };
	ULONG Ignored = 0;

	*BytesReturned = 0;
	if (Output == NULL || OutputLength < sizeof(PIDDB_CACHE_ENUM_OUTPUT))
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Output, sizeof(PIDDB_CACHE_ENUM_OUTPUT));
	if (!NT_SUCCESS(QuerySystemTables(&Tables, sizeof(Tables), &Ignored)))
		return STATUS_UNSUCCESSFUL;
	if (Tables.PiDDBCacheTable == 0)
		return STATUS_NOT_FOUND;

	Output->TableAddress = Tables.PiDDBCacheTable;

	auto* Table = reinterpret_cast<PRTL_AVL_TABLE>(Tables.PiDDBCacheTable);
	auto* TableLocal = reinterpret_cast<PRTL_AVL_TABLE_LOCAL>(Tables.PiDDBCacheTable);
	if (TableLocal != NULL)
		Output->TotalCount = TableLocal->NumberGenericTableElements;

	PVOID RestartKey = NULL;
	for (ULONG Index = 0; Index < PIDDB_CACHE_MAX_ENTRIES; ++Index)
	{
		PVOID Element = RtlEnumerateGenericTableWithoutSplayingAvl(Table, &RestartKey);
		if (Element == NULL)
			break;

		auto* Entry = reinterpret_cast<PPIDDB_CACHE_ENTRY_LOCAL>(Element);
		PIDDB_CACHE_ENTRY_INFO* OutEntry = &Output->Entries[Output->Count];
		OutEntry->Index = Output->Count;
		OutEntry->Address = reinterpret_cast<ULONG_PTR>(Entry);

		__try
		{
			OutEntry->TimeDateStamp = Entry->TimeDateStamp;
			OutEntry->LoadStatus = Entry->LoadStatus;
			if (Entry->DriverName.Buffer != NULL && Entry->DriverName.Length != 0)
			{
				RtlStringCbCopyNW(OutEntry->DriverName, sizeof(OutEntry->DriverName),
					Entry->DriverName.Buffer, Entry->DriverName.Length);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			RtlStringCchCopyW(OutEntry->DriverName, RTL_NUMBER_OF(OutEntry->DriverName), L"<invalid>");
			OutEntry->LoadStatus = STATUS_ACCESS_VIOLATION;
		}

		++Output->Count;
	}

	if (Output->TotalCount < Output->Count)
		Output->TotalCount = Output->Count;

	*BytesReturned = sizeof(PIDDB_CACHE_ENUM_OUTPUT);
	return STATUS_SUCCESS;
}

static VOID
MdvSetDriverMessage(
	_Out_writes_(Capacity) PWCHAR Buffer,
	_In_ SIZE_T Capacity,
	_In_ PCWSTR Format,
	...
)
{
	if (Buffer == NULL || Capacity == 0)
		return;

	va_list VaList;
	va_start(VaList, Format);
	RtlStringCchVPrintfW(Buffer, Capacity, Format, VaList);
	va_end(VaList);
}

static VOID
MdvInitDriverControlOutput(
	_Out_opt_ PDRIVER_CONTROL_OUTPUT Output,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (Output != NULL && OutputLength >= sizeof(DRIVER_CONTROL_OUTPUT))
	{
		RtlZeroMemory(Output, sizeof(DRIVER_CONTROL_OUTPUT));
		*BytesReturned = sizeof(DRIVER_CONTROL_OUTPUT);
	}
}

static NTSTATUS
MdvBuildServiceRegistryPath(
	_In_ PCWSTR ServiceName,
	_Out_writes_(260) PWCHAR RegistryPath
)
{
	if (ServiceName == NULL || ServiceName[0] == L'\0' || RegistryPath == NULL)
		return STATUS_INVALID_PARAMETER;

	return RtlStringCchPrintfW(RegistryPath, 260,
		L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws", ServiceName);
}

static NTSTATUS
MdvOpenServicesRoot(
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE KeyHandle
)
{
	UNICODE_STRING Path;
	RtlInitUnicodeString(&Path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services");
	OBJECT_ATTRIBUTES Attributes;
	InitializeObjectAttributes(&Attributes, &Path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	return ZwOpenKey(KeyHandle, DesiredAccess, &Attributes);
}

static NTSTATUS
MdvOpenServiceKey(
	_In_ PCWSTR ServiceName,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE KeyHandle,
	_Out_writes_opt_(260) PWCHAR RegistryPath
)
{
	WCHAR FullPath[260] = { 0 };
	NTSTATUS Status = MdvBuildServiceRegistryPath(ServiceName, FullPath);
	if (!NT_SUCCESS(Status))
		return Status;

	if (RegistryPath != NULL)
		RtlStringCchCopyW(RegistryPath, 260, FullPath);

	UNICODE_STRING Path;
	RtlInitUnicodeString(&Path, FullPath);
	OBJECT_ATTRIBUTES Attributes;
	InitializeObjectAttributes(&Attributes, &Path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	return ZwOpenKey(KeyHandle, DesiredAccess, &Attributes);
}

static NTSTATUS
MdvQueryStringValue(
	_In_ HANDLE KeyHandle,
	_In_ PCWSTR ValueName,
	_Out_writes_(CharCapacity) PWCHAR Buffer,
	_In_ ULONG CharCapacity
)
{
	if (Buffer == NULL || CharCapacity == 0)
		return STATUS_INVALID_PARAMETER;

	Buffer[0] = L'\0';
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, ValueName);

	ULONG ResultLength = 0;
	NTSTATUS Status = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation,
		NULL, 0, &ResultLength);
	if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW)
		return Status;

	PKEY_VALUE_PARTIAL_INFORMATION Value =
		static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(AllocPoolZero(ResultLength));
	if (Value == NULL)
		return STATUS_NO_MEMORY;

	Status = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation,
		Value, ResultLength, &ResultLength);
	if (NT_SUCCESS(Status) &&
		(Value->Type == REG_SZ || Value->Type == REG_EXPAND_SZ || Value->Type == REG_MULTI_SZ))
	{
		ULONG CharCount = min(Value->DataLength / sizeof(WCHAR), (CharCapacity - 1));
		RtlCopyMemory(Buffer, Value->Data, CharCount * sizeof(WCHAR));
		Buffer[CharCount] = L'\0';
	}
	else if (NT_SUCCESS(Status))
	{
		Status = STATUS_OBJECT_TYPE_MISMATCH;
	}

	ExFreePoolWithTag(Value, POOL_TAG);
	return Status;
}

static NTSTATUS
MdvQueryDwordValue(
	_In_ HANDLE KeyHandle,
	_In_ PCWSTR ValueName,
	_Out_ PULONG ValueOut
)
{
	if (ValueOut == NULL)
		return STATUS_INVALID_PARAMETER;
	*ValueOut = 0;

	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, ValueName);
	KEY_VALUE_PARTIAL_INFORMATION Info = {};
	ULONG ResultLength = 0;
	NTSTATUS Status = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation,
		&Info, sizeof(Info), &ResultLength);
	if (!NT_SUCCESS(Status))
		return Status;
	if (Info.Type != REG_DWORD || Info.DataLength < sizeof(ULONG))
		return STATUS_OBJECT_TYPE_MISMATCH;
	RtlCopyMemory(ValueOut, Info.Data, sizeof(ULONG));
	return STATUS_SUCCESS;
}

static ULONG
MdvQueryDriverState(
	_In_ PCWSTR ServiceName
)
{
	if (ServiceName == NULL || ServiceName[0] == L'\0')
		return SERVICE_STOPPED;

	WCHAR ObjectPath[160] = { 0 };
	if (!NT_SUCCESS(RtlStringCchPrintfW(
		ObjectPath, RTL_NUMBER_OF(ObjectPath), L"\\Driver\\%ws", ServiceName)))
		return SERVICE_STOPPED;

	UNICODE_STRING DriverPath;
	RtlInitUnicodeString(&DriverPath, ObjectPath);
	PDRIVER_OBJECT DriverObject = NULL;
	NTSTATUS Status = ObReferenceObjectByName(&DriverPath,
		OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL,
		reinterpret_cast<PVOID*>(&DriverObject));
	if (!NT_SUCCESS(Status))
		return SERVICE_STOPPED;

	ObfDereferenceObject(DriverObject);
	return SERVICE_RUNNING;
}

static NTSTATUS
MdvQueryDriverRuntimeInfo(
	_In_ PCWSTR ServiceName,
	_Out_opt_ PULONG State,
	_Out_opt_ PULONG_PTR DriverObjectAddress,
	_Out_opt_ PULONG_PTR ImageBase,
	_Out_opt_ PULONG ImageSize
)
{
	if (State != NULL)
		*State = SERVICE_STOPPED;
	if (DriverObjectAddress != NULL)
		*DriverObjectAddress = 0;
	if (ImageBase != NULL)
		*ImageBase = 0;
	if (ImageSize != NULL)
		*ImageSize = 0;
	if (ServiceName == NULL || ServiceName[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	WCHAR ObjectPath[160] = { 0 };
	NTSTATUS Status = RtlStringCchPrintfW(
		ObjectPath, RTL_NUMBER_OF(ObjectPath), L"\\Driver\\%ws", ServiceName);
	if (!NT_SUCCESS(Status))
		return Status;

	UNICODE_STRING DriverPath;
	RtlInitUnicodeString(&DriverPath, ObjectPath);
	PDRIVER_OBJECT DriverObject = NULL;
	Status = ObReferenceObjectByName(&DriverPath,
		OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL,
		reinterpret_cast<PVOID*>(&DriverObject));
	if (!NT_SUCCESS(Status))
		return Status;

	if (State != NULL)
		*State = SERVICE_RUNNING;
	if (DriverObjectAddress != NULL)
		*DriverObjectAddress = reinterpret_cast<ULONG_PTR>(DriverObject);
	if (ImageBase != NULL)
		*ImageBase = reinterpret_cast<ULONG_PTR>(DriverObject->DriverStart);
	if (ImageSize != NULL)
		*ImageSize = DriverObject->DriverSize;

	ObfDereferenceObject(DriverObject);
	return STATUS_SUCCESS;
}

static NTSTATUS
MdvFillDriverEntryFromKey(
	_In_ HANDLE KeyHandle,
	_In_ PCWSTR ServiceName,
	_Out_ PDRIVER_ENUM_ENTRY Entry
)
{
	if (Entry == NULL)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Entry, sizeof(*Entry));
	RtlStringCchCopyW(Entry->ServiceName, RTL_NUMBER_OF(Entry->ServiceName), ServiceName);
	Entry->Type = SERVICE_KERNEL_DRIVER;
	(void)MdvBuildServiceRegistryPath(ServiceName, Entry->RegistryPath);
	(void)MdvQueryDriverRuntimeInfo(ServiceName, &Entry->State, &Entry->DriverObject, &Entry->ImageBase, &Entry->ImageSize);

	if (!NT_SUCCESS(MdvQueryStringValue(KeyHandle, L"DisplayName",
		Entry->DisplayName, RTL_NUMBER_OF(Entry->DisplayName))))
	{
		RtlStringCchCopyW(Entry->DisplayName, RTL_NUMBER_OF(Entry->DisplayName), ServiceName);
	}

	(void)MdvQueryStringValue(KeyHandle, L"ImagePath", Entry->ImagePath, RTL_NUMBER_OF(Entry->ImagePath));
	(void)MdvQueryDwordValue(KeyHandle, L"Type", &Entry->Type);
	(void)MdvQueryDwordValue(KeyHandle, L"Start", &Entry->StartType);
	(void)MdvQueryDwordValue(KeyHandle, L"ErrorControl", &Entry->ErrorControl);
	return STATUS_SUCCESS;
}

NTSTATUS
EnumerateDrivers(
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	if (BytesReturned == NULL)
		return STATUS_INVALID_PARAMETER;
	*BytesReturned = 0;
	if (OutputBuffer == NULL || OutputLength < sizeof(DRIVER_ENUM_HEADER))
		return STATUS_BUFFER_TOO_SMALL;

	PDRIVER_ENUM_HEADER Header = static_cast<PDRIVER_ENUM_HEADER>(OutputBuffer);
	RtlZeroMemory(Header, sizeof(*Header));

	HANDLE ServicesKey = NULL;
	NTSTATUS Status = MdvOpenServicesRoot(KEY_ENUMERATE_SUB_KEYS, &ServicesKey);
	if (!NT_SUCCESS(Status))
	{
		Header->NtStatus = Status;
		MdvSetDriverMessage(Header->Message, RTL_NUMBER_OF(Header->Message),
			L"Failed to open Services root (0x%08X).", Status);
		*BytesReturned = sizeof(DRIVER_ENUM_HEADER);
		return STATUS_SUCCESS;
	}

	const ULONG Capacity = (OutputLength - sizeof(DRIVER_ENUM_HEADER)) / sizeof(DRIVER_ENUM_ENTRY);
	ULONG Count = 0;
	ULONG DriverCount = 0;
	PDRIVER_ENUM_ENTRY Entries = reinterpret_cast<PDRIVER_ENUM_ENTRY>(Header + 1);
	PUCHAR NameBuffer = NULL;
	ULONG NameBufferLength = 512;

	for (ULONG Index = 0;; ++Index)
	{
		if (NameBuffer == NULL)
		{
			NameBuffer = static_cast<PUCHAR>(AllocPoolZero(NameBufferLength));
			if (NameBuffer == NULL)
			{
				Status = STATUS_NO_MEMORY;
				break;
			}
		}

		ULONG ResultLength = 0;
		Status = ZwEnumerateKey(ServicesKey, Index, KeyBasicInformation,
			NameBuffer, NameBufferLength, &ResultLength);
		if (Status == STATUS_NO_MORE_ENTRIES)
		{
			Status = STATUS_SUCCESS;
			break;
		}
		if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
		{
			ExFreePoolWithTag(NameBuffer, POOL_TAG);
			NameBuffer = static_cast<PUCHAR>(AllocPoolZero(ResultLength));
			NameBufferLength = ResultLength;
			if (NameBuffer == NULL)
			{
				Status = STATUS_NO_MEMORY;
				break;
			}
			--Index;
			continue;
		}
		if (!NT_SUCCESS(Status))
			break;

		PKEY_BASIC_INFORMATION KeyInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(NameBuffer);
		const ULONG NameChars = min(KeyInfo->NameLength / sizeof(WCHAR), 127ul);
		WCHAR ServiceName[128] = { 0 };
		RtlCopyMemory(ServiceName, KeyInfo->Name, NameChars * sizeof(WCHAR));
		ServiceName[NameChars] = L'\0';

		HANDLE ServiceKey = NULL;
		if (!NT_SUCCESS(MdvOpenServiceKey(ServiceName, KEY_QUERY_VALUE, &ServiceKey, NULL)))
			continue;

		ULONG Type = 0;
		if (!NT_SUCCESS(MdvQueryDwordValue(ServiceKey, L"Type", &Type)) ||
			(Type & SERVICE_KERNEL_DRIVER) == 0)
		{
			ZwClose(ServiceKey);
			continue;
		}

		++DriverCount;
		if (Count < Capacity)
		{
			(void)MdvFillDriverEntryFromKey(ServiceKey, ServiceName, &Entries[Count]);
			++Count;
		}

		ZwClose(ServiceKey);
	}

	if (NameBuffer != NULL)
		ExFreePoolWithTag(NameBuffer, POOL_TAG);
	ZwClose(ServicesKey);

	Header->NtStatus = Status;
	Header->Count = DriverCount;
	if (NT_SUCCESS(Status))
	{
		MdvSetDriverMessage(Header->Message, RTL_NUMBER_OF(Header->Message),
			L"Kernel enumerated %lu driver service(s), returned %lu item(s).",
			DriverCount, Count);
	}
	else
	{
		MdvSetDriverMessage(Header->Message, RTL_NUMBER_OF(Header->Message),
			L"Driver enumeration failed after %lu item(s) (0x%08X).",
			Count, Status);
	}
	*BytesReturned = sizeof(DRIVER_ENUM_HEADER) + Count * sizeof(DRIVER_ENUM_ENTRY);
	return STATUS_SUCCESS;
}

NTSTATUS
LoadDriverKernel(
	_In_ PDRIVER_CONTROL_INPUT Input,
	_Out_opt_ PDRIVER_CONTROL_OUTPUT Output,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	if (Input == NULL || BytesReturned == NULL)
		return STATUS_INVALID_PARAMETER;

	DRIVER_CONTROL_INPUT LocalInput = *Input;
	LocalInput.ServiceName[RTL_NUMBER_OF(LocalInput.ServiceName) - 1] = L'\0';
	LocalInput.ImagePath[RTL_NUMBER_OF(LocalInput.ImagePath) - 1] = L'\0';
	MdvInitDriverControlOutput(Output, OutputLength, BytesReturned);
	if (LocalInput.ServiceName[0] == L'\0' || LocalInput.ImagePath[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	WCHAR RegistryPath[260] = { 0 };
	HANDLE ServiceKey = NULL;
	NTSTATUS Status = MdvOpenServiceKey(LocalInput.ServiceName,
		KEY_SET_VALUE | KEY_QUERY_VALUE, &ServiceKey, RegistryPath);
	if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		(void)MdvBuildServiceRegistryPath(LocalInput.ServiceName, RegistryPath);
		UNICODE_STRING Path;
		RtlInitUnicodeString(&Path, RegistryPath);
		OBJECT_ATTRIBUTES Attributes;
		InitializeObjectAttributes(&Attributes, &Path,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		Status = ZwCreateKey(&ServiceKey, KEY_SET_VALUE | KEY_QUERY_VALUE,
			&Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	}

	if (!NT_SUCCESS(Status))
	{
		if (Output != NULL)
		{
			Output->NtStatus = Status;
			MdvSetDriverMessage(Output->Message, RTL_NUMBER_OF(Output->Message),
				L"Failed to open/create service key for %ws (0x%08X).", LocalInput.ServiceName, Status);
		}
		return STATUS_SUCCESS;
	}

	UNICODE_STRING ValueName;
	ULONG Dword = SERVICE_KERNEL_DRIVER;
	RtlInitUnicodeString(&ValueName, L"Type");
	Status = ZwSetValueKey(ServiceKey, &ValueName, 0, REG_DWORD, &Dword, sizeof(Dword));
	if (NT_SUCCESS(Status))
	{
		Dword = SERVICE_DEMAND_START;
		RtlInitUnicodeString(&ValueName, L"Start");
		Status = ZwSetValueKey(ServiceKey, &ValueName, 0, REG_DWORD, &Dword, sizeof(Dword));
	}
	if (NT_SUCCESS(Status))
	{
		Dword = SERVICE_ERROR_NORMAL;
		RtlInitUnicodeString(&ValueName, L"ErrorControl");
		Status = ZwSetValueKey(ServiceKey, &ValueName, 0, REG_DWORD, &Dword, sizeof(Dword));
	}
	if (NT_SUCCESS(Status))
	{
		UNICODE_STRING PathData;
		RtlInitUnicodeString(&PathData, LocalInput.ImagePath);
		RtlInitUnicodeString(&ValueName, L"ImagePath");
		Status = ZwSetValueKey(ServiceKey, &ValueName, 0, REG_EXPAND_SZ,
			PathData.Buffer, PathData.Length + sizeof(WCHAR));
	}
	if (NT_SUCCESS(Status))
	{
		UNICODE_STRING DisplayData;
		RtlInitUnicodeString(&DisplayData, LocalInput.ServiceName);
		RtlInitUnicodeString(&ValueName, L"DisplayName");
		Status = ZwSetValueKey(ServiceKey, &ValueName, 0, REG_SZ,
			DisplayData.Buffer, DisplayData.Length + sizeof(WCHAR));
	}
	ZwClose(ServiceKey);

	if (NT_SUCCESS(Status))
	{
		UNICODE_STRING DriverPath;
		RtlInitUnicodeString(&DriverPath, RegistryPath);
		Status = ZwLoadDriver(&DriverPath);
		if (Status == STATUS_IMAGE_ALREADY_LOADED)
			Status = STATUS_SUCCESS;
	}

	if (Output != NULL)
	{
		Output->NtStatus = Status;
		(void)MdvQueryDriverRuntimeInfo(LocalInput.ServiceName, &Output->State, &Output->DriverObject, &Output->ImageBase, &Output->ImageSize);
		Output->Type = SERVICE_KERNEL_DRIVER;
		Output->StartType = SERVICE_DEMAND_START;
		Output->ErrorControl = SERVICE_ERROR_NORMAL;
		RtlStringCchCopyW(Output->RegistryPath, RTL_NUMBER_OF(Output->RegistryPath), RegistryPath);
		RtlStringCchCopyW(Output->ImagePath, RTL_NUMBER_OF(Output->ImagePath), LocalInput.ImagePath);
		if (NT_SUCCESS(Status))
		{
			MdvSetDriverMessage(Output->Message, RTL_NUMBER_OF(Output->Message),
				L"Kernel loaded %ws | Object=0x%p | Base=0x%p | Size=0x%X | Reg=%ws | Image=%ws.",
				LocalInput.ServiceName,
				reinterpret_cast<PVOID>(Output->DriverObject),
				reinterpret_cast<PVOID>(Output->ImageBase),
				Output->ImageSize,
				Output->RegistryPath,
				Output->ImagePath);
		}
		else
		{
			MdvSetDriverMessage(Output->Message, RTL_NUMBER_OF(Output->Message),
				L"Kernel failed to load driver %ws (0x%08X).", LocalInput.ServiceName, Status);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS
UnloadDriverKernel(
	_In_ PDRIVER_CONTROL_INPUT Input,
	_Out_opt_ PDRIVER_CONTROL_OUTPUT Output,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	if (Input == NULL || BytesReturned == NULL)
		return STATUS_INVALID_PARAMETER;

	DRIVER_CONTROL_INPUT LocalInput = *Input;
	LocalInput.ServiceName[RTL_NUMBER_OF(LocalInput.ServiceName) - 1] = L'\0';
	MdvInitDriverControlOutput(Output, OutputLength, BytesReturned);
	if (LocalInput.ServiceName[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	WCHAR RegistryPath[260] = { 0 };
	(void)MdvBuildServiceRegistryPath(LocalInput.ServiceName, RegistryPath);
	HANDLE ServiceKey = NULL;
	NTSTATUS Status = MdvOpenServiceKey(LocalInput.ServiceName,
		KEY_QUERY_VALUE | DELETE, &ServiceKey, NULL);
	if (NT_SUCCESS(Status) && Output != NULL)
	{
		(void)MdvQueryStringValue(ServiceKey, L"ImagePath", Output->ImagePath, RTL_NUMBER_OF(Output->ImagePath));
		(void)MdvQueryDwordValue(ServiceKey, L"Type", &Output->Type);
		(void)MdvQueryDwordValue(ServiceKey, L"Start", &Output->StartType);
		(void)MdvQueryDwordValue(ServiceKey, L"ErrorControl", &Output->ErrorControl);
	}

	UNICODE_STRING DriverPath;
	RtlInitUnicodeString(&DriverPath, RegistryPath);
	NTSTATUS UnloadStatus = ZwUnloadDriver(&DriverPath);
	if (UnloadStatus == STATUS_OBJECT_NAME_NOT_FOUND)
		UnloadStatus = STATUS_SUCCESS;

	if (ServiceKey != NULL)
		ZwClose(ServiceKey);

	if (Output != NULL)
	{
		Output->NtStatus = UnloadStatus;
		(void)MdvQueryDriverRuntimeInfo(LocalInput.ServiceName, &Output->State, &Output->DriverObject, &Output->ImageBase, &Output->ImageSize);
		RtlStringCchCopyW(Output->RegistryPath, RTL_NUMBER_OF(Output->RegistryPath), RegistryPath);
		if (NT_SUCCESS(UnloadStatus))
		{
			MdvSetDriverMessage(Output->Message, RTL_NUMBER_OF(Output->Message),
				L"Kernel unloaded %ws | State=%lu | Reg=%ws | Image=%ws.",
				LocalInput.ServiceName, Output->State, Output->RegistryPath, Output->ImagePath);
		}
		else
		{
			MdvSetDriverMessage(Output->Message, RTL_NUMBER_OF(Output->Message),
				L"Kernel failed to unload driver %ws (0x%08X).", LocalInput.ServiceName, UnloadStatus);
		}
	}
	return STATUS_SUCCESS;
}
