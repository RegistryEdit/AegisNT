
typedef struct _MDV2_SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} MDV2_SYSTEM_THREAD_INFORMATION, *PMDV2_SYSTEM_THREAD_INFORMATION;

typedef struct _MDV2_SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	MDV2_SYSTEM_THREAD_INFORMATION Threads[1];
} MDV2_SYSTEM_PROCESS_INFORMATION, *PMDV2_SYSTEM_PROCESS_INFORMATION;

typedef struct _MDV2_BIGPOOL_ENTRY {
	union { PVOID VirtualAddress; ULONG_PTR NonPaged : 1; };
	ULONG_PTR SizeInBytes;
	union { UCHAR Tag[4]; ULONG TagUlong; };
} MDV2_BIGPOOL_ENTRY, *PMDV2_BIGPOOL_ENTRY;

typedef struct _MDV2_BIGPOOL_INFORMATION {
	ULONG Count;
	MDV2_BIGPOOL_ENTRY AllocatedInfo[1];
} MDV2_BIGPOOL_INFORMATION, *PMDV2_BIGPOOL_INFORMATION;

typedef struct _MDV2_CODE_INTEGRITY_INFORMATION {
	ULONG Length;
	ULONG CodeIntegrityOptions;
} MDV2_CODE_INTEGRITY_INFORMATION;

typedef struct _MDV2_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN Enabled;
	BOOLEAN NotPresent;
} MDV2_KERNEL_DEBUGGER_INFORMATION;

typedef struct _MDV2_SECURE_BOOT_INFORMATION {
	BOOLEAN SecureBootEnabled;
	BOOLEAN SecureBootCapable;
} MDV2_SECURE_BOOT_INFORMATION;

static VOID Mdv2InitHeader(PMDV2_LIST_HEADER Header, NTSTATUS Status, ULONG Source, ULONG Confidence)
{
	RtlZeroMemory(Header, sizeof(*Header));
	Header->Size = sizeof(*Header);
	Header->Version = MDV2_PROTOCOL_VERSION;
	Header->Status = Status;
	Header->Source = Source;
	Header->Confidence = Confidence;
}

static VOID Mdv2InitRecord(PMDV2_RECORD Record, ULONG Kind, ULONG Source)
{
	RtlZeroMemory(Record, sizeof(*Record));
	Record->Size = sizeof(*Record);
	Record->Kind = Kind;
	Record->Source = Source;
	Record->Confidence = Mdv2ConfidenceHigh;
	Record->Status = STATUS_SUCCESS;
}

static VOID Mdv2CopyUnicode(PWCHAR Destination, SIZE_T Capacity, PCUNICODE_STRING Source)
{
	if (Destination == NULL || Capacity == 0) return;
	Destination[0] = L'\0';
	if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) return;
	SIZE_T Chars = min((SIZE_T)(Source->Length / sizeof(WCHAR)), Capacity - 1);
	RtlCopyMemory(Destination, Source->Buffer, Chars * sizeof(WCHAR));
	Destination[Chars] = L'\0';
}

static VOID Mdv2CopyAnsi(PWCHAR Destination, SIZE_T Capacity, PCSTR Source)
{
	if (Destination == NULL || Capacity == 0) return;
	Destination[0] = L'\0';
	if (Source == NULL) return;
	SIZE_T Index = 0;
	while (Index + 1 < Capacity && Source[Index] != '\0') {
		Destination[Index] = (WCHAR)(UCHAR)Source[Index];
		++Index;
	}
	Destination[Index] = L'\0';
}

static BOOLEAN Mdv2IsObjectQueryResizeStatus(NTSTATUS Status)
{
	return Status == STATUS_INFO_LENGTH_MISMATCH ||
		Status == STATUS_BUFFER_OVERFLOW ||
		Status == STATUS_BUFFER_TOO_SMALL;
}

typedef struct _MDV_OBJECT_NAME_INFORMATION_LOCAL {
	UNICODE_STRING Name;
	WCHAR Buffer[1];
} MDV_OBJECT_NAME_INFORMATION_LOCAL, * PMDV_OBJECT_NAME_INFORMATION_LOCAL;

typedef struct _MDV_OBJECT_TYPE_INFORMATION_LOCAL {
	UNICODE_STRING TypeName;
	WCHAR Buffer[1];
} MDV_OBJECT_TYPE_INFORMATION_LOCAL, * PMDV_OBJECT_TYPE_INFORMATION_LOCAL;

static NTSTATUS Mdv2QueryObjectBuffer(
	_In_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS InfoClass,
	_Outptr_result_bytebuffer_(*BufferLength) PVOID* Buffer,
	_Out_ PULONG BufferLength
)
{
	if (Buffer == NULL || BufferLength == NULL)
		return STATUS_INVALID_PARAMETER;

	*Buffer = NULL;
	*BufferLength = 0;

	ULONG Size = 0x200;
	for (ULONG Attempt = 0; Attempt < 8; ++Attempt)
	{
		PVOID Local = ExAllocatePool2(POOL_FLAG_PAGED, Size, POOL_TAG);
		if (Local == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;

		ULONG ReturnLength = 0;
		NTSTATUS Status = ZwQueryObject(Handle, InfoClass, Local, Size, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			*Buffer = Local;
			*BufferLength = Size;
			return STATUS_SUCCESS;
		}

		ExFreePoolWithTag(Local, POOL_TAG);
		if (!Mdv2IsObjectQueryResizeStatus(Status))
			return Status;

		Size = ReturnLength > Size ? ReturnLength + 0x100 : Size * 2;
	}

	return STATUS_BUFFER_TOO_SMALL;
}

static VOID Mdv2PopulateHandleMetadata(
	_In_ ULONG ProcessId,
	_In_ ULONG_PTR HandleValue,
	_Out_ PMDV2_RECORD Record
)
{
	if (Record == NULL || ProcessId == 0 || HandleValue == 0)
		return;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
		return;

	HANDLE ProcessHandle = NULL;
	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
		PROCESS_DUP_HANDLE, *PsProcessType, KernelMode, &ProcessHandle);
	ObfDereferenceObject(Process);
	if (!NT_SUCCESS(Status))
		return;

	HANDLE Duplicate = NULL;
	Status = ZwDuplicateObject(ProcessHandle, (HANDLE)HandleValue, ZwCurrentProcess(),
		&Duplicate, 0, 0, DUPLICATE_SAME_ACCESS);
	ZwClose(ProcessHandle);
	if (!NT_SUCCESS(Status) || Duplicate == NULL)
		return;

	PVOID TypeBuffer = NULL;
	ULONG TypeBufferLength = 0;
	Status = Mdv2QueryObjectBuffer(Duplicate, static_cast<OBJECT_INFORMATION_CLASS>(2), &TypeBuffer, &TypeBufferLength);
	if (NT_SUCCESS(Status) && TypeBuffer != NULL)
	{
		PMDV_OBJECT_TYPE_INFORMATION_LOCAL TypeInfo = (PMDV_OBJECT_TYPE_INFORMATION_LOCAL)TypeBuffer;
		Mdv2CopyUnicode(Record->TypeName, RTL_NUMBER_OF(Record->TypeName), &TypeInfo->TypeName);
		ExFreePoolWithTag(TypeBuffer, POOL_TAG);
	}

	PVOID NameBuffer = NULL;
	ULONG NameBufferLength = 0;
	Status = Mdv2QueryObjectBuffer(Duplicate, static_cast<OBJECT_INFORMATION_CLASS>(1), &NameBuffer, &NameBufferLength);
	if (NT_SUCCESS(Status) && NameBuffer != NULL)
	{
		PMDV_OBJECT_NAME_INFORMATION_LOCAL NameInfo = (PMDV_OBJECT_NAME_INFORMATION_LOCAL)NameBuffer;
		Mdv2CopyUnicode(Record->Path, RTL_NUMBER_OF(Record->Path), &NameInfo->Name);
		ExFreePoolWithTag(NameBuffer, POOL_TAG);
	}

	if (Record->Detail[0] == L'\0')
		RtlStringCchPrintfW(Record->Detail, RTL_NUMBER_OF(Record->Detail),
			L"TypeIndex=%llu", Record->Value[2]);

	ZwClose(Duplicate);
}

static NTSTATUS Mdv2ValidateRequest(const MDV2_QUERY_INPUT* Input, ULONG InputLength)
{
	if (Input == NULL || InputLength < sizeof(MDV2_QUERY_INPUT)) return STATUS_INVALID_PARAMETER;
	if (Input->Size < sizeof(MDV2_QUERY_INPUT) || Input->Version != MDV2_PROTOCOL_VERSION) return STATUS_REVISION_MISMATCH;
	if (Input->MaxEntries > MDV2_MAX_PAGE_RECORDS) return STATUS_INVALID_PARAMETER;
	return STATUS_SUCCESS;
}

static ULONG Mdv2OutputCapacity(ULONG OutputLength)
{
	if (OutputLength < FIELD_OFFSET(MDV2_LIST_OUTPUT, Records)) return 0;
	return min((OutputLength - FIELD_OFFSET(MDV2_LIST_OUTPUT, Records)) / sizeof(MDV2_RECORD), MDV2_MAX_PAGE_RECORDS);
}

static NTSTATUS Mdv2QuerySystemBuffer(ULONG Class, PVOID* Buffer, PULONG Length)
{
	*Buffer = NULL; *Length = 0;
	ULONG Required = 0;
	NTSTATUS Status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)Class, NULL, 0, &Required);
	if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL &&
		Status != STATUS_BUFFER_OVERFLOW) return Status;
	ULONG Capacity = max(Required + PAGE_SIZE, 1u << 20);
	for (ULONG Attempt = 0; Attempt < 8; ++Attempt) {
		PVOID Local = ExAllocatePool2(POOL_FLAG_NON_PAGED, Capacity, POOL_TAG);
		if (Local == NULL) return STATUS_INSUFFICIENT_RESOURCES;
		ULONG Returned = 0;
		Status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)Class, Local, Capacity, &Returned);
		if (NT_SUCCESS(Status)) {
			*Buffer = Local; *Length = Returned ? Returned : Capacity;
			return STATUS_SUCCESS;
		}
		ExFreePoolWithTag(Local, POOL_TAG);
		if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL &&
			Status != STATUS_BUFFER_OVERFLOW) return Status;
		Capacity = max(Capacity * 2, Returned + PAGE_SIZE);
	}
	return STATUS_BUFFER_TOO_SMALL;
}

static PMDV2_SYSTEM_PROCESS_INFORMATION Mdv2FindProcess(PVOID Buffer, ULONG ProcessId)
{
	auto Entry = (PMDV2_SYSTEM_PROCESS_INFORMATION)Buffer;
	for (;;) {
		if (HandleToULong(Entry->UniqueProcessId) == ProcessId) return Entry;
		if (Entry->NextEntryOffset == 0) break;
		Entry = (PMDV2_SYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
	}
	return NULL;
}

static VOID Mdv2WriteText(_Out_writes_(Capacity) PWCHAR Destination, SIZE_T Capacity, _In_opt_ PCWSTR Value)
{
	if (Destination == NULL || Capacity == 0)
		return;
	Destination[0] = L'\0';
	if (Value == NULL || Value[0] == L'\0')
		return;
	RtlStringCchCopyW(Destination, Capacity, Value);
}

static VOID Mdv2AppendEprocessRecord(
	_Inout_ PMDV2_LIST_OUTPUT Output,
	_In_ ULONG Capacity,
	_In_ ULONG ProcessId,
	_In_ PCWSTR Member,
	_In_opt_ PCWSTR DisplayValue,
	_In_opt_ PCWSTR Notes,
	_In_ ULONG64 FieldAddress,
	_In_ ULONG64 Offset,
	_In_ ULONG64 RawValue,
	_In_ ULONG Source,
	_In_ ULONG Confidence,
	_In_ NTSTATUS Status
)
{
	if (Output == NULL || Output->Header.ReturnedCount >= Capacity)
		return;

	PMDV2_RECORD Record = &Output->Records[Output->Header.ReturnedCount++];
	Mdv2InitRecord(Record, 13, Source);
	Record->ProcessId = ProcessId;
	Record->Address = FieldAddress;
	Record->Value[0] = Offset;
	Record->Value[1] = RawValue;
	Record->Confidence = Confidence;
	Record->Status = Status;
	Mdv2WriteText(Record->Name, RTL_NUMBER_OF(Record->Name), Member);
	Mdv2WriteText(Record->Path, RTL_NUMBER_OF(Record->Path), DisplayValue);
	Mdv2WriteText(Record->Detail, RTL_NUMBER_OF(Record->Detail), Notes);
}

static NTSTATUS Mdv2OpenProcessHandle(
	_In_ PEPROCESS Process,
	_Out_ PHANDLE ProcessHandle
)
{
	if (Process == NULL || ProcessHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	*ProcessHandle = NULL;
	return ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
		PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, ProcessHandle);
}

static NTSTATUS Mdv2QueryProcessImagePath(
	_In_ PEPROCESS Process,
	_Out_writes_(Capacity) PWCHAR Destination,
	_In_ SIZE_T Capacity
)
{
	if (Destination == NULL || Capacity == 0)
		return STATUS_INVALID_PARAMETER;

	Destination[0] = L'\0';
	typedef NTSTATUS(NTAPI* PLocateName)(PEPROCESS, PUNICODE_STRING*);
	UNICODE_STRING Routine;
	RtlInitUnicodeString(&Routine, L"SeLocateProcessImageName");
	auto Locate = (PLocateName)MmGetSystemRoutineAddress(&Routine);
	if (Locate == NULL)
		return STATUS_PROCEDURE_NOT_FOUND;

	PUNICODE_STRING ImageName = NULL;
	NTSTATUS Status = Locate(Process, &ImageName);
	if (NT_SUCCESS(Status) && ImageName != NULL)
	{
		Mdv2CopyUnicode(Destination, Capacity, ImageName);
		ExFreePool(ImageName);
	}
	return Status;
}

static NTSTATUS Mdv2FindActiveProcessLinksOffset(
	_Out_ PULONG Offset
)
{
	if (Offset == NULL)
		return STATUS_INVALID_PARAMETER;

	*Offset = 0;

	PEPROCESS SystemProc = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(4), &SystemProc);
	if (!NT_SUCCESS(Status))
		return Status;

	ULONG TestOffset = 0x448;
	PLIST_ENTRY Entry = (PLIST_ENTRY)((PUCHAR)SystemProc + TestOffset);

	__try
	{
		if ((ULONG_PTR)Entry->Flink > 0xFFFF000000000000ULL &&
			(ULONG_PTR)Entry->Blink > 0xFFFF000000000000ULL)
		{
			*Offset = TestOffset;
			ObfDereferenceObject(SystemProc);
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	for (ULONG Off = 0x200; Off <= 0x800; Off += sizeof(ULONG_PTR))
	{
		PLIST_ENTRY Candidate = (PLIST_ENTRY)((PUCHAR)SystemProc + Off);
		__try
		{
			if ((ULONG_PTR)Candidate->Flink < 0xFFFF000000000000ULL ||
				(ULONG_PTR)Candidate->Blink < 0xFFFF000000000000ULL)
				continue;
			if (Candidate->Flink->Blink != Candidate)
				continue;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}

		*Offset = Off;
		ObfDereferenceObject(SystemProc);
		return STATUS_SUCCESS;
	}

	ObfDereferenceObject(SystemProc);
	return STATUS_NOT_FOUND;
}

static NTSTATUS Mdv2QueryEprocess(
	_In_ const MDV2_QUERY_INPUT* Query,
	_Inout_ PMDV2_LIST_OUTPUT Output,
	_In_ ULONG OutputLength
)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength),
		Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0)
		return STATUS_BUFFER_TOO_SMALL;
	if (Query->ProcessId == 0)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS ProcessObject = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Query->ProcessId), &ProcessObject);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceVersionProfile, Mdv2ConfidenceMedium);
	if (!NT_SUCCESS(Status))
		return Status;

	const ULONG64 EprocessBase = (ULONG64)(ULONG_PTR)ProcessObject;
	WCHAR Text[260] = {};
	WCHAR Notes[256] = {};

	RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", ProcessObject);
	Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"EPROCESS",
		Text, L"Kernel process object base", EprocessBase, 0, EprocessBase,
		Mdv2SourcePublicApi, Mdv2ConfidenceHigh, STATUS_SUCCESS);

	PVOID SysBuffer = NULL;
	ULONG SysLength = 0;
	Status = Mdv2QuerySystemBuffer(5, &SysBuffer, &SysLength);
	if (NT_SUCCESS(Status))
	{
		auto Spi = Mdv2FindProcess(SysBuffer, Query->ProcessId);
		if (Spi != NULL)
		{
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", HandleToULong(Spi->UniqueProcessId));
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"UniqueProcessId",
				Text, L"Resolved from SystemProcessInformation", 0, 0,
				HandleToULong(Spi->UniqueProcessId), Mdv2SourceSystemInformation,
				Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", HandleToULong(Spi->InheritedFromUniqueProcessId));
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"InheritedFromUniqueProcessId",
				Text, L"Resolved from SystemProcessInformation", 0, 0,
				HandleToULong(Spi->InheritedFromUniqueProcessId), Mdv2SourceSystemInformation,
				Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", Spi->SessionId);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"SessionId",
				Text, L"Resolved from SystemProcessInformation", 0, 0,
				Spi->SessionId, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%lld", Spi->CreateTime.QuadPart);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"CreateTime",
				Text, L"FILETIME tick value", 0, 0, (ULONG64)Spi->CreateTime.QuadPart,
				Mdv2SourceSystemInformation, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%llu", (ULONG64)Spi->UniqueProcessKey);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"UniqueProcessKey",
				Text, L"Resolved from SystemProcessInformation", 0, 0,
				(ULONG64)Spi->UniqueProcessKey, Mdv2SourceSystemInformation,
				Mdv2ConfidenceMedium, STATUS_SUCCESS);

			if (Spi->ImageName.Buffer != NULL && Spi->ImageName.Length != 0)
			{
				Mdv2CopyUnicode(Text, RTL_NUMBER_OF(Text), &Spi->ImageName);
				Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ImageFileName",
					Text, L"Short image name from SystemProcessInformation", 0, 0, 0,
					Mdv2SourceSystemInformation, Mdv2ConfidenceHigh, STATUS_SUCCESS);
			}
		}
		ExFreePoolWithTag(SysBuffer, POOL_TAG);
	}

	Status = Mdv2QueryProcessImagePath(ProcessObject, Text, RTL_NUMBER_OF(Text));
	Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"SeAuditProcessCreationInfo.ImageFileName",
		NT_SUCCESS(Status) ? Text : L"-",
		L"Resolved via SeLocateProcessImageName", 0, 0, 0,
		Mdv2SourcePublicApi, NT_SUCCESS(Status) ? Mdv2ConfidenceHigh : Mdv2ConfidenceUnavailable, Status);

	HANDLE ProcessHandle = NULL;
	Status = Mdv2OpenProcessHandle(ProcessObject, &ProcessHandle);
	if (NT_SUCCESS(Status))
	{
		PROCESS_BASIC_INFORMATION Pbi = {};
		NTSTATUS PbiStatus = ZwQueryInformationProcess(
			ProcessHandle, ProcessBasicInformation, &Pbi, sizeof(Pbi), NULL);
		if (NT_SUCCESS(PbiStatus))
		{
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", Pbi.PebBaseAddress);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Peb",
				Text, L"User-mode PEB address", (ULONG64)(ULONG_PTR)Pbi.PebBaseAddress, 0,
				(ULONG64)(ULONG_PTR)Pbi.PebBaseAddress, Mdv2SourceProcessEnvironment,
				Mdv2ConfidenceHigh, STATUS_SUCCESS);
		}
		else
		{
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Peb",
				L"-", L"ZwQueryInformationProcess(ProcessBasicInformation)", 0, 0, 0,
				Mdv2SourceProcessEnvironment, Mdv2ConfidenceUnavailable, PbiStatus);
		}

		PVOID Wow64Peb = NULL;
		ULONG Returned = 0;
		NTSTATUS Wow64Status = ZwQueryInformationProcess(
			ProcessHandle, (PROCESSINFOCLASS)26, &Wow64Peb, sizeof(Wow64Peb), &Returned);
		if (NT_SUCCESS(Wow64Status))
		{
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", Wow64Peb);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Wow64Process",
				Text, L"ZwQueryInformationProcess(ProcessWow64Information)", (ULONG64)(ULONG_PTR)Wow64Peb, 0,
				(ULONG64)(ULONG_PTR)Wow64Peb, Mdv2SourceProcessEnvironment,
				Mdv2ConfidenceHigh, STATUS_SUCCESS);
		}
		else
		{
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Wow64Process",
				L"-", L"ZwQueryInformationProcess(ProcessWow64Information)", 0, 0, 0,
				Mdv2SourceProcessEnvironment, Mdv2ConfidenceUnavailable, Wow64Status);
		}

		ZwClose(ProcessHandle);
	}

	if (!G_ActiveLinksOffsetFound)
	{
		Status = Mdv2FindActiveProcessLinksOffset(&G_ActiveProcessLinksOffset);
		G_ActiveLinksOffsetFound = NT_SUCCESS(Status);
	}
	if (G_ActiveLinksOffsetFound)
	{
		PLIST_ENTRY Links = (PLIST_ENTRY)((PUCHAR)ProcessObject + G_ActiveProcessLinksOffset);
		__try
		{
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", Links);
			RtlStringCchPrintfW(Notes, RTL_NUMBER_OF(Notes), L"Offset 0x%X", G_ActiveProcessLinksOffset);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ActiveProcessLinks",
				Text, Notes, (ULONG64)(ULONG_PTR)Links, G_ActiveProcessLinksOffset,
				(ULONG64)(ULONG_PTR)Links, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", Links->Flink);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ActiveProcessLinks.Flink",
				Text, L"Forward link", (ULONG64)(ULONG_PTR)&Links->Flink, G_ActiveProcessLinksOffset,
				(ULONG64)(ULONG_PTR)Links->Flink, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", Links->Blink);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ActiveProcessLinks.Blink",
				Text, L"Backward link", (ULONG64)(ULONG_PTR)&Links->Blink,
				G_ActiveProcessLinksOffset + sizeof(PVOID),
				(ULONG64)(ULONG_PTR)Links->Blink, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			if (G_ActiveProcessLinksOffset >= sizeof(PVOID))
			{
				ULONG_PTR UniquePidValue = *(volatile ULONG_PTR*)((PUCHAR)ProcessObject + G_ActiveProcessLinksOffset - sizeof(PVOID));
				RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%llu", (ULONG64)UniquePidValue);
				RtlStringCchPrintfW(Notes, RTL_NUMBER_OF(Notes), L"Inferred from ActiveProcessLinks - sizeof(PVOID), offset 0x%X",
					G_ActiveProcessLinksOffset - (ULONG)sizeof(PVOID));
				Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"UniqueProcessId.Inferred",
					Text, Notes,
					EprocessBase + G_ActiveProcessLinksOffset - sizeof(PVOID),
					G_ActiveProcessLinksOffset - sizeof(PVOID), (ULONG64)UniquePidValue,
					Mdv2SourceVersionProfile, Mdv2ConfidenceMedium, STATUS_SUCCESS);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ActiveProcessLinks",
				L"-", L"Direct EPROCESS read faulted", 0, G_ActiveProcessLinksOffset, 0,
				Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, GetExceptionCode());
		}
	}
	else
	{
		Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"ActiveProcessLinks",
			L"-", L"Offset discovery failed", 0, 0, 0,
			Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, STATUS_NOT_FOUND);
	}

	if (!G_TokenOffsetFound)
	{
		Status = FindTokenOffset(&G_TokenOffset, ProcessObject);
		G_TokenOffsetFound = NT_SUCCESS(Status);
	}
	if (G_TokenOffsetFound)
	{
		__try
		{
			ULONG_PTR RawToken = *(volatile ULONG_PTR*)((PUCHAR)ProcessObject + G_TokenOffset);
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", (PVOID)RawToken);
			RtlStringCchPrintfW(Notes, RTL_NUMBER_OF(Notes), L"Offset 0x%X", G_TokenOffset);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Token",
				Text, Notes, EprocessBase + G_TokenOffset, G_TokenOffset, (ULONG64)RawToken,
				Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%p", (PVOID)(RawToken & ~0xFULL));
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Token.Object",
				Text, L"EX_FAST_REF object pointer", EprocessBase + G_TokenOffset, G_TokenOffset,
				(ULONG64)(RawToken & ~0xFULL), Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Token",
				L"-", L"Direct EPROCESS read faulted", 0, G_TokenOffset, 0,
				Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, GetExceptionCode());
		}
	}
	else
	{
		Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Token",
			L"-", L"Offset discovery failed", 0, 0, 0,
			Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, STATUS_NOT_FOUND);
	}

	if (G_PplOffset == 0)
		FindPplOffset(&G_PplOffset);
	if (G_PplOffset != 0)
	{
		__try
		{
			PPS_PROTECTION Protection = (PPS_PROTECTION)((PUCHAR)ProcessObject + G_PplOffset);
			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"0x%02X", Protection->Level);
			RtlStringCchPrintfW(Notes, RTL_NUMBER_OF(Notes), L"Offset 0x%X", G_PplOffset);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection",
				Text, Notes, EprocessBase + G_PplOffset, G_PplOffset,
				Protection->Level, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", (ULONG)Protection->s.Type);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection.Type",
				Text, L"PS_PROTECTED_TYPE", EprocessBase + G_PplOffset, G_PplOffset,
				(ULONG)Protection->s.Type, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", (ULONG)Protection->s.Signer);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection.Signer",
				Text, L"PS_PROTECTED_SIGNER", EprocessBase + G_PplOffset, G_PplOffset,
				(ULONG)Protection->s.Signer, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);

			RtlStringCchPrintfW(Text, RTL_NUMBER_OF(Text), L"%u", (ULONG)Protection->s.Audit);
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection.Audit",
				Text, L"Audit bit", EprocessBase + G_PplOffset, G_PplOffset,
				(ULONG)Protection->s.Audit, Mdv2SourceSignatureScan, Mdv2ConfidenceHigh, STATUS_SUCCESS);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection",
				L"-", L"Direct EPROCESS read faulted", 0, G_PplOffset, 0,
				Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, GetExceptionCode());
		}
	}
	else
	{
		Mdv2AppendEprocessRecord(Output, Capacity, Query->ProcessId, L"Protection",
			L"-", L"Offset discovery failed", 0, 0, 0,
			Mdv2SourceSignatureScan, Mdv2ConfidenceUnavailable, STATUS_NOT_FOUND);
	}

	Output->Header.TotalCount = Output->Header.ReturnedCount;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) +
		Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ObfDereferenceObject(ProcessObject);
	return STATUS_SUCCESS;
}

static NTSTATUS Mdv2QueryProcess(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	if (Mdv2OutputCapacity(OutputLength) == 0) return STATUS_BUFFER_TOO_SMALL;
	PVOID Buffer = NULL; ULONG Length = 0;
	NTSTATUS Status = Mdv2QuerySystemBuffer(5, &Buffer, &Length);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	if (!NT_SUCCESS(Status)) return Status;
	auto Process = Mdv2FindProcess(Buffer, Query->ProcessId);
	if (Process == NULL) { ExFreePoolWithTag(Buffer, POOL_TAG); Output->Header.Status = STATUS_NOT_FOUND; return STATUS_NOT_FOUND; }
	auto Record = &Output->Records[0];
	Mdv2InitRecord(Record, 1, Mdv2SourceSystemInformation);
	Record->ProcessId = Query->ProcessId;
	Record->Value[0] = HandleToULong(Process->InheritedFromUniqueProcessId);
	Record->Value[1] = Process->NumberOfThreads;
	Record->Value[2] = Process->HandleCount;
	Record->Value[3] = Process->SessionId;
	Record->Value[4] = Process->CreateTime.QuadPart;
	Record->Value[5] = Process->UserTime.QuadPart;
	Record->Value[6] = Process->KernelTime.QuadPart;
	Record->Value[7] = Process->PrivatePageCount;
	Record->SizeBytes = Process->WorkingSetSize;
	Mdv2CopyUnicode(Record->Name, RTL_NUMBER_OF(Record->Name), &Process->ImageName);
	PEPROCESS ProcessObject = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Query->ProcessId), &ProcessObject))) {
		Record->Address = (ULONG64)(ULONG_PTR)ProcessObject;
		RtlStringCchPrintfW(Record->Detail, RTL_NUMBER_OF(Record->Detail), L"0x%p",
			(PVOID)Process->UniqueProcessKey);
		typedef NTSTATUS (NTAPI* PLocateName)(PEPROCESS, PUNICODE_STRING*);
		UNICODE_STRING Routine; RtlInitUnicodeString(&Routine, L"SeLocateProcessImageName");
		auto Locate = (PLocateName)MmGetSystemRoutineAddress(&Routine);
		PUNICODE_STRING ImageName = NULL;
		if (Locate != NULL && NT_SUCCESS(Locate(ProcessObject, &ImageName)) && ImageName != NULL) {
			Mdv2CopyUnicode(Record->Path, RTL_NUMBER_OF(Record->Path), ImageName);
			ExFreePool(ImageName);
		}
		ObfDereferenceObject(ProcessObject);
	}
	Output->Header.TotalCount = Output->Header.ReturnedCount = 1;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Buffer, POOL_TAG);
	return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateThreads(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PVOID Buffer = NULL; ULONG Length = 0;
	NTSTATUS Status = Mdv2QuerySystemBuffer(5, &Buffer, &Length);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	if (!NT_SUCCESS(Status)) return Status;
	auto Process = Mdv2FindProcess(Buffer, Query->ProcessId);
	if (Process == NULL) { ExFreePoolWithTag(Buffer, POOL_TAG); return STATUS_NOT_FOUND; }
	ULONG Start = (ULONG)min(Query->Cursor, (ULONG64)Process->NumberOfThreads);
	ULONG End = min(Process->NumberOfThreads, Start + Capacity);
	for (ULONG Index = Start; Index < End; ++Index) {
		auto& Thread = Process->Threads[Index]; auto& Record = Output->Records[Output->Header.ReturnedCount++];
		Mdv2InitRecord(&Record, 2, Mdv2SourceSystemInformation);
		Record.ProcessId = HandleToULong(Thread.ClientId.UniqueProcess);
		Record.ThreadId = HandleToULong(Thread.ClientId.UniqueThread);
		Record.Address = (ULONG64)(ULONG_PTR)Thread.StartAddress;
		Record.Value[0] = Thread.Priority; Record.Value[1] = Thread.BasePriority;
		Record.Value[2] = Thread.ThreadState; Record.Value[3] = Thread.WaitReason;
		Record.Value[4] = Thread.ContextSwitches; Record.Value[5] = Thread.CreateTime.QuadPart;
		Record.Value[6] = Thread.UserTime.QuadPart; Record.Value[7] = Thread.KernelTime.QuadPart;
	}
	Output->Header.TotalCount = Process->NumberOfThreads;
	Output->Header.NextCursor = End < Process->NumberOfThreads ? End : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Buffer, POOL_TAG); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateHandles(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PVOID Buffer = NULL; ULONG Length = 0;
	NTSTATUS Status = Mdv2QuerySystemBuffer(64, &Buffer, &Length);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	if (!NT_SUCCESS(Status)) return Status;
	auto Handles = (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;
	ULONG64 MatchIndex = 0; ULONG64 Cursor = Query->Cursor;
	for (ULONG_PTR Index = 0; Index < Handles->NumberOfHandles; ++Index) {
		auto& Handle = Handles->Handles[Index];
		if (Query->ProcessId != 0 && Handle.UniqueProcessId != Query->ProcessId) continue;
		if (MatchIndex++ < Cursor) continue;
		if (Output->Header.ReturnedCount >= Capacity) continue;
		auto& Record = Output->Records[Output->Header.ReturnedCount++];
		Mdv2InitRecord(&Record, 3, Mdv2SourceSystemInformation);
		Record.ProcessId = (ULONG)Handle.UniqueProcessId; Record.Address = (ULONG64)(ULONG_PTR)Handle.Object;
		Record.Value[0] = Handle.HandleValue; Record.Value[1] = Handle.GrantedAccess;
		Record.Value[2] = Handle.ObjectTypeIndex; Record.Value[3] = Handle.HandleAttributes;
		Mdv2PopulateHandleMetadata(Record.ProcessId, Handle.HandleValue, &Record);
	}
	Output->Header.TotalCount = (ULONG)min(MatchIndex, (ULONG64)MAXULONG);
	ULONG64 Consumed = Cursor + Output->Header.ReturnedCount;
	Output->Header.NextCursor = Consumed < MatchIndex ? Consumed : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Buffer, POOL_TAG); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateKernelModules(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PMY_MODULE_INFO Modules = GetSystemModuleInfo();
	Mdv2InitHeader(&Output->Header, Modules ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	if (Modules == NULL) return STATUS_UNSUCCESSFUL;
	ULONG Start = (ULONG)min(Query->Cursor, (ULONG64)Modules->ModulesCount);
	ULONG End = min(Modules->ModulesCount, Start + Capacity);
	for (ULONG Index = Start; Index < End; ++Index) {
		auto& Module = Modules->Modules[Index]; auto& Record = Output->Records[Output->Header.ReturnedCount++];
		Mdv2InitRecord(&Record, 4, Mdv2SourceSystemInformation);
		Record.Address = (ULONG64)(ULONG_PTR)Module.ImageBase; Record.SizeBytes = Module.ImageSize;
		Record.Value[0] = Module.Flags; Record.Value[1] = Module.LoadOrderIndex; Record.Value[2] = Module.LoadCount;
		Mdv2CopyAnsi(Record.Path, RTL_NUMBER_OF(Record.Path), (PCSTR)Module.FullPathName);
		Mdv2CopyAnsi(Record.Name, RTL_NUMBER_OF(Record.Name), (PCSTR)Module.FullPathName + Module.OffsetToFileName);
	}
	Output->Header.TotalCount = Modules->ModulesCount; Output->Header.NextCursor = End < Modules->ModulesCount ? End : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Modules, POOL_TAG); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateBigPool(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PVOID Buffer = NULL; ULONG Length = 0; NTSTATUS Status = Mdv2QuerySystemBuffer(66, &Buffer, &Length);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	if (!NT_SUCCESS(Status)) return Status;
	auto Pools = (PMDV2_BIGPOOL_INFORMATION)Buffer; ULONG Start = (ULONG)min(Query->Cursor, (ULONG64)Pools->Count);
	ULONG End = min(Pools->Count, Start + Capacity);
	for (ULONG Index = Start; Index < End; ++Index) {
		auto& Pool = Pools->AllocatedInfo[Index]; auto& Record = Output->Records[Output->Header.ReturnedCount++];
		Mdv2InitRecord(&Record, 5, Mdv2SourceSystemInformation);
		Record.Address = ((ULONG64)(ULONG_PTR)Pool.VirtualAddress) & ~1ull; Record.SizeBytes = Pool.SizeInBytes;
		Record.Flags = ((ULONG_PTR)Pool.VirtualAddress & 1) ? 1u : 0u;
		for (ULONG Char = 0; Char < 4; ++Char) Record.Name[Char] = (WCHAR)Pool.Tag[Char];
		Record.Name[4] = L'\0';
	}
	Output->Header.TotalCount = Pools->Count; Output->Header.NextCursor = End < Pools->Count ? End : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Buffer, POOL_TAG); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateMemory(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0 || Query->ProcessId == 0) return STATUS_INVALID_PARAMETER;
	PEPROCESS Process = NULL; NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Query->ProcessId), &Process);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceMemoryMap, Mdv2ConfidenceHigh); if (!NT_SUCCESS(Status)) return Status;
	HANDLE ProcessHandle = NULL;
	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &ProcessHandle);
	ObfDereferenceObject(Process); Output->Header.Status = Status; if (!NT_SUCCESS(Status)) return Status;
	ULONG_PTR Address = Query->Cursor; ULONG64 Seen = 0;
	while (Address < (ULONG_PTR)MmHighestUserAddress && Output->Header.ReturnedCount < Capacity) {
		MEMORY_BASIC_INFORMATION Info = {}; SIZE_T Returned = 0;
		Status = ZwQueryVirtualMemory(ProcessHandle, (PVOID)Address, MemoryBasicInformation, &Info, sizeof(Info), &Returned);
		if (!NT_SUCCESS(Status) || Info.RegionSize == 0) break;
		auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 10, Mdv2SourceMemoryMap);
		Record.ProcessId = Query->ProcessId; Record.Address = (ULONG64)(ULONG_PTR)Info.BaseAddress; Record.SizeBytes = Info.RegionSize;
		Record.Value[0] = (ULONG64)(ULONG_PTR)Info.AllocationBase; Record.Value[1] = Info.AllocationProtect;
		Record.Value[2] = Info.State; Record.Value[3] = Info.Protect; Record.Value[4] = Info.Type;
		Address = (ULONG_PTR)Info.BaseAddress + Info.RegionSize; ++Seen;
		if (Address <= (ULONG_PTR)Info.BaseAddress) break;
	}
	ZwClose(ProcessHandle);
	Output->Header.Status = NT_SUCCESS(Status) || Status == STATUS_INVALID_ADDRESS ? STATUS_SUCCESS : Status;
	Output->Header.TotalCount = (ULONG)Seen; Output->Header.NextCursor = Address < (ULONG_PTR)MmHighestUserAddress ? Address : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	return STATUS_SUCCESS;
}

typedef struct _MDV2_MEMORY_SECTION_NAME { UNICODE_STRING SectionFileName; } MDV2_MEMORY_SECTION_NAME;

static NTSTATUS Mdv2EnumerateProcessModules(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0 || Query->ProcessId == 0) return STATUS_INVALID_PARAMETER;
	PEPROCESS Process = NULL; NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Query->ProcessId), &Process);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceMemoryMap, Mdv2ConfidenceMedium); if (!NT_SUCCESS(Status)) return Status;
	HANDLE ProcessHandle = NULL; Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION,
		*PsProcessType, KernelMode, &ProcessHandle); ObfDereferenceObject(Process);
	Output->Header.Status = Status; if (!NT_SUCCESS(Status)) return Status;
	ULONG_PTR Address = Query->Cursor; ULONG_PTR LastAllocation = 0; ULONG Total = 0;
	while (Address < (ULONG_PTR)MmHighestUserAddress && Output->Header.ReturnedCount < Capacity) {
		MEMORY_BASIC_INFORMATION Info = {}; SIZE_T Returned = 0;
		Status = ZwQueryVirtualMemory(ProcessHandle, (PVOID)Address, MemoryBasicInformation, &Info, sizeof(Info), &Returned);
		if (!NT_SUCCESS(Status) || Info.RegionSize == 0) break;
		if (Info.Type == MEM_IMAGE && (ULONG_PTR)Info.AllocationBase != LastAllocation) {
			LastAllocation = (ULONG_PTR)Info.AllocationBase; ++Total;
			auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 4, Mdv2SourceMemoryMap);
			Record.Confidence = Mdv2ConfidenceMedium; Record.ProcessId = Query->ProcessId;
			Record.Address = (ULONG64)LastAllocation; Record.SizeBytes = Info.RegionSize; Record.Value[0] = Info.AllocationProtect;
			UCHAR NameBuffer[2048] = {}; SIZE_T NameReturned = 0;
			if (NT_SUCCESS(ZwQueryVirtualMemory(ProcessHandle, Info.AllocationBase, (MEMORY_INFORMATION_CLASS)2,
				NameBuffer, sizeof(NameBuffer), &NameReturned))) {
				auto Section = (MDV2_MEMORY_SECTION_NAME*)NameBuffer;
				Mdv2CopyUnicode(Record.Path, RTL_NUMBER_OF(Record.Path), &Section->SectionFileName);
				PCWSTR Slash = wcsrchr(Record.Path, L'\\');
				RtlStringCchCopyW(Record.Name, RTL_NUMBER_OF(Record.Name), Slash ? Slash + 1 : Record.Path);
			}
		}
		Address = (ULONG_PTR)Info.BaseAddress + Info.RegionSize; if (Address <= (ULONG_PTR)Info.BaseAddress) break;
	}
	ZwClose(ProcessHandle); Output->Header.Status = STATUS_SUCCESS; Output->Header.TotalCount = Total;
	Output->Header.NextCursor = Address < (ULONG_PTR)MmHighestUserAddress ? Address : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2QueryMemory(PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = Mdv2OutputCapacity(OutputLength);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	Mdv2InitHeader(&Output->Header, STATUS_SUCCESS, Mdv2SourcePublicApi, Mdv2ConfidenceHigh);
	PPHYSICAL_MEMORY_RANGE Ranges = MmGetPhysicalMemoryRanges();
	if (Ranges == NULL) { Output->Header.Status = STATUS_INSUFFICIENT_RESOURCES; }
	else {
		for (ULONG Index = 0; Ranges[Index].NumberOfBytes.QuadPart != 0; ++Index) {
			++Output->Header.TotalCount;
			if (Output->Header.ReturnedCount >= Capacity) continue;
			auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 11, Mdv2SourcePublicApi);
			Record.Address = Ranges[Index].BaseAddress.QuadPart;
			Record.SizeBytes = Ranges[Index].NumberOfBytes.QuadPart;
			Record.Value[0] = Index;
			RtlStringCchPrintfW(Record.Name, RTL_NUMBER_OF(Record.Name), L"Physical Range %lu", Index);
		}
		ExFreePool(Ranges);
	}
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	return Output->Header.Status;
}

static NTSTATUS Mdv2EnumerateMiniFilters(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PFLT_FILTER Filters[256] = {}; ULONG Count = 0; NTSTATUS Status = FltEnumerateFilters(Filters, RTL_NUMBER_OF(Filters), &Count);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourcePublicApi, Mdv2ConfidenceHigh); if (!NT_SUCCESS(Status)) return Status;
	ULONG Start = (ULONG)min(Query->Cursor, (ULONG64)Count); ULONG End = min(Count, Start + Capacity);
	for (ULONG Index = 0; Index < Count; ++Index) {
		if (Index >= Start && Index < End) {
			UCHAR InfoBuffer[1024] = {}; ULONG Returned = 0;
			NTSTATUS InfoStatus = FltGetFilterInformation(Filters[Index], FilterAggregateBasicInformation, InfoBuffer, sizeof(InfoBuffer), &Returned);
			auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 12, Mdv2SourcePublicApi); Record.Status = InfoStatus;
			if (NT_SUCCESS(InfoStatus)) {
				auto Info = (PFILTER_AGGREGATE_BASIC_INFORMATION)InfoBuffer; Record.Flags = Info->Flags;
				if (Info->Flags & FLTFL_AGGREGATE_INFO_IS_MINIFILTER) {
					UNICODE_STRING FilterName = { Info->Type.MiniFilter.FilterNameLength, Info->Type.MiniFilter.FilterNameLength, (PWCHAR)(InfoBuffer + Info->Type.MiniFilter.FilterNameBufferOffset) };
					UNICODE_STRING Altitude = { Info->Type.MiniFilter.FilterAltitudeLength, Info->Type.MiniFilter.FilterAltitudeLength, (PWCHAR)(InfoBuffer + Info->Type.MiniFilter.FilterAltitudeBufferOffset) };
					Mdv2CopyUnicode(Record.Name, RTL_NUMBER_OF(Record.Name), &FilterName); Mdv2CopyUnicode(Record.Detail, RTL_NUMBER_OF(Record.Detail), &Altitude);
					Record.Value[0] = Info->Type.MiniFilter.FrameID; Record.Value[1] = Info->Type.MiniFilter.NumberOfInstances;
				}
			}
		}
		FltObjectDereference(Filters[Index]);
	}
	Output->Header.TotalCount = Count; Output->Header.NextCursor = End < Count ? End : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD); return STATUS_SUCCESS;
}

static BOOLEAN Mdv2ContainsAnsiInsensitive(PCSTR Text, PCSTR Needle)
{
	if (Text == NULL || Needle == NULL) return FALSE;
	for (SIZE_T Start = 0; Text[Start] != '\0'; ++Start) {
		SIZE_T Index = 0;
		while (Needle[Index] != '\0' && Text[Start + Index] != '\0') {
			CHAR A = Text[Start + Index], B = Needle[Index];
			if (A >= 'A' && A <= 'Z') A += 'a' - 'A'; if (B >= 'A' && B <= 'Z') B += 'a' - 'A';
			if (A != B) break; ++Index;
		}
		if (Needle[Index] == '\0') return TRUE;
	}
	return FALSE;
}

static NTSTATUS Mdv2EnumerateNetworkComponents(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength, BOOLEAN Wfp)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	PMY_MODULE_INFO Modules = GetSystemModuleInfo();
	Mdv2InitHeader(&Output->Header, Modules ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, Mdv2SourceCrossView, Mdv2ConfidenceMedium); if (Modules == NULL) return STATUS_UNSUCCESSFUL;
	ULONG Match = 0;
	for (ULONG Index = 0; Index < Modules->ModulesCount; ++Index) {
		PCSTR Path = (PCSTR)Modules->Modules[Index].FullPathName;
		BOOLEAN Relevant = Wfp ? (Mdv2ContainsAnsiInsensitive(Path, "wfp") || Mdv2ContainsAnsiInsensitive(Path, "netio") || Mdv2ContainsAnsiInsensitive(Path, "tcpip"))
			: (Mdv2ContainsAnsiInsensitive(Path, "ndis") || Mdv2ContainsAnsiInsensitive(Path, "netadapter") || Mdv2ContainsAnsiInsensitive(Path, "netio"));
		if (!Relevant) continue;
		if (Match++ < Query->Cursor) continue; if (Output->Header.ReturnedCount >= Capacity) continue;
		auto& Module = Modules->Modules[Index]; auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, Wfp ? 13 : 14, Mdv2SourceCrossView);
		Record.Confidence = Mdv2ConfidenceMedium; Record.Address = (ULONG64)(ULONG_PTR)Module.ImageBase; Record.SizeBytes = Module.ImageSize;
		Mdv2CopyAnsi(Record.Name, RTL_NUMBER_OF(Record.Name), Path + Module.OffsetToFileName); Mdv2CopyAnsi(Record.Path, RTL_NUMBER_OF(Record.Path), Path);
	}
	Output->Header.TotalCount = Match; ULONG64 Consumed = Query->Cursor + Output->Header.ReturnedCount; Output->Header.NextCursor = Consumed < Match ? Consumed : 0;
	Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ExFreePoolWithTag(Modules, POOL_TAG); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2EnumerateObjects(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = min(Mdv2OutputCapacity(OutputLength), Query->MaxEntries ? Query->MaxEntries : MDV2_MAX_PAGE_RECORDS);
	if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	UNICODE_STRING Path; RtlInitUnicodeString(&Path, Query->Path[0] ? Query->Path : L"\\Driver");
	OBJECT_ATTRIBUTES Attributes; InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	HANDLE Directory = NULL; NTSTATUS Status = ZwOpenDirectoryObject(&Directory, DIRECTORY_QUERY, &Attributes);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceObjectManager, Mdv2ConfidenceHigh);
	if (!NT_SUCCESS(Status)) return Status;
	ULONG Context = (ULONG)Query->Cursor; BOOLEAN Restart = Query->Cursor == 0;
	for (; Output->Header.ReturnedCount < Capacity;) {
		UCHAR Local[1024] = {}; ULONG Returned = 0;
		Status = ZwQueryDirectoryObject(Directory, Local, sizeof(Local), TRUE, Restart, &Context, &Returned);
		Restart = FALSE;
		if (Status == STATUS_NO_MORE_ENTRIES) { Status = STATUS_SUCCESS; break; }
		if (!NT_SUCCESS(Status)) break;
		auto Info = (POBJECT_DIRECTORY_INFORMATION)Local; auto& Record = Output->Records[Output->Header.ReturnedCount++];
		Mdv2InitRecord(&Record, 6, Mdv2SourceObjectManager);
		Mdv2CopyUnicode(Record.Name, RTL_NUMBER_OF(Record.Name), &Info->Name);
		Mdv2CopyUnicode(Record.TypeName, RTL_NUMBER_OF(Record.TypeName), &Info->TypeName);
		RtlStringCchCopyW(Record.Path, RTL_NUMBER_OF(Record.Path), Query->Path[0] ? Query->Path : L"\\Driver");
	}
	Output->Header.Status = Status; Output->Header.NextCursor = NT_SUCCESS(Status) && Output->Header.ReturnedCount == Capacity ? Context : 0;
	Output->Header.TotalCount = Context; Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ZwClose(Directory); return Status;
}

static NTSTATUS Mdv2QueryDriver(const MDV2_QUERY_INPUT* Query, PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = Mdv2OutputCapacity(OutputLength); if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
	WCHAR ObjectName[160] = {}; NTSTATUS Status = RtlStringCchPrintfW(ObjectName, RTL_NUMBER_OF(ObjectName), L"\\Driver\\%ws", Query->Name);
	Mdv2InitHeader(&Output->Header, Status, Mdv2SourceObjectManager, Mdv2ConfidenceHigh); if (!NT_SUCCESS(Status)) return Status;
	UNICODE_STRING Name; RtlInitUnicodeString(&Name, ObjectName); PDRIVER_OBJECT DriverObject = NULL;
	Status = ObReferenceObjectByName(&Name, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);
	Output->Header.Status = Status; if (!NT_SUCCESS(Status)) return Status;
	auto& Overview = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Overview, 7, Mdv2SourceObjectManager);
	Overview.Address = (ULONG64)(ULONG_PTR)DriverObject; Overview.SizeBytes = DriverObject->DriverSize;
	Overview.Value[0] = (ULONG64)(ULONG_PTR)DriverObject->DriverStart; Overview.Value[1] = (ULONG64)(ULONG_PTR)DriverObject->DeviceObject;
	RtlStringCchCopyW(Overview.Name, RTL_NUMBER_OF(Overview.Name), Query->Name); Mdv2CopyUnicode(Overview.Path, RTL_NUMBER_OF(Overview.Path), &DriverObject->DriverName);
	for (ULONG Major = 0; Major <= IRP_MJ_MAXIMUM_FUNCTION && Output->Header.ReturnedCount < Capacity; ++Major) {
		auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 8, Mdv2SourceObjectManager);
		Record.Address = (ULONG64)(ULONG_PTR)DriverObject->MajorFunction[Major]; Record.Value[0] = Major;
		RtlStringCchPrintfW(Record.Name, RTL_NUMBER_OF(Record.Name), L"IRP_MJ_%u", Major);
	}
	if (DriverObject->FastIoDispatch != NULL && Output->Header.ReturnedCount < Capacity) {
		const PFAST_IO_DISPATCH FastIo = DriverObject->FastIoDispatch;
		const struct { PCWSTR Name; PVOID Address; } Entries[] = {
			{ L"FastIoCheckIfPossible", (PVOID)FastIo->FastIoCheckIfPossible },
			{ L"FastIoRead", (PVOID)FastIo->FastIoRead },
			{ L"FastIoWrite", (PVOID)FastIo->FastIoWrite },
			{ L"FastIoQueryBasicInfo", (PVOID)FastIo->FastIoQueryBasicInfo },
			{ L"FastIoQueryStandardInfo", (PVOID)FastIo->FastIoQueryStandardInfo },
			{ L"FastIoLock", (PVOID)FastIo->FastIoLock },
			{ L"FastIoUnlockSingle", (PVOID)FastIo->FastIoUnlockSingle },
			{ L"FastIoUnlockAll", (PVOID)FastIo->FastIoUnlockAll },
			{ L"FastIoUnlockAllByKey", (PVOID)FastIo->FastIoUnlockAllByKey },
			{ L"FastIoDeviceControl", (PVOID)FastIo->FastIoDeviceControl },
			{ L"AcquireFileForNtCreateSection", (PVOID)FastIo->AcquireFileForNtCreateSection },
			{ L"ReleaseFileForNtCreateSection", (PVOID)FastIo->ReleaseFileForNtCreateSection },
			{ L"FastIoDetachDevice", (PVOID)FastIo->FastIoDetachDevice },
			{ L"FastIoQueryNetworkOpenInfo", (PVOID)FastIo->FastIoQueryNetworkOpenInfo },
			{ L"AcquireForModWrite", (PVOID)FastIo->AcquireForModWrite },
			{ L"MdlRead", (PVOID)FastIo->MdlRead },
			{ L"MdlReadComplete", (PVOID)FastIo->MdlReadComplete },
			{ L"PrepareMdlWrite", (PVOID)FastIo->PrepareMdlWrite },
			{ L"MdlWriteComplete", (PVOID)FastIo->MdlWriteComplete },
			{ L"FastIoReadCompressed", (PVOID)FastIo->FastIoReadCompressed },
			{ L"FastIoWriteCompressed", (PVOID)FastIo->FastIoWriteCompressed },
			{ L"MdlReadCompleteCompressed", (PVOID)FastIo->MdlReadCompleteCompressed },
			{ L"MdlWriteCompleteCompressed", (PVOID)FastIo->MdlWriteCompleteCompressed },
			{ L"FastIoQueryOpen", (PVOID)FastIo->FastIoQueryOpen },
			{ L"ReleaseForModWrite", (PVOID)FastIo->ReleaseForModWrite },
			{ L"AcquireForCcFlush", (PVOID)FastIo->AcquireForCcFlush },
			{ L"ReleaseForCcFlush", (PVOID)FastIo->ReleaseForCcFlush }
		};
		for (ULONG Index = 0; Index < RTL_NUMBER_OF(Entries) && Output->Header.ReturnedCount < Capacity; ++Index) {
			if (Entries[Index].Address == NULL) continue;
			auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 16, Mdv2SourceObjectManager);
			Record.Address = (ULONG64)(ULONG_PTR)Entries[Index].Address;
			Record.Value[0] = (ULONG64)(ULONG_PTR)FastIo; Record.Value[1] = Index;
			RtlStringCchCopyW(Record.Name, RTL_NUMBER_OF(Record.Name), Entries[Index].Name);
		}
	}
	for (PDEVICE_OBJECT Device = DriverObject->DeviceObject; Device != NULL && Output->Header.ReturnedCount < Capacity; Device = Device->NextDevice) {
		auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 15, Mdv2SourceObjectManager);
		Record.Address = (ULONG64)(ULONG_PTR)Device; Record.Value[0] = (ULONG64)(ULONG_PTR)Device->AttachedDevice;
		Record.Value[1] = Device->DeviceType; Record.Value[2] = Device->Characteristics; Record.Value[3] = Device->Flags;
		Record.Value[4] = Device->StackSize; Record.Value[5] = (ULONG64)(ULONG_PTR)Device->NextDevice;
		Record.Value[6] = (ULONG64)(ULONG_PTR)Device->DriverObject; Record.Value[7] = Device->AlignmentRequirement;
		RtlStringCchCopyW(Record.Name, RTL_NUMBER_OF(Record.Name), L"DeviceObject");
	}
	Output->Header.TotalCount = Output->Header.ReturnedCount; Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	ObfDereferenceObject(DriverObject); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2QuerySecurity(PMDV2_LIST_OUTPUT Output, ULONG OutputLength)
{
	ULONG Capacity = Mdv2OutputCapacity(OutputLength); if (Capacity < 6) return STATUS_BUFFER_TOO_SMALL;
	Mdv2InitHeader(&Output->Header, STATUS_SUCCESS, Mdv2SourceSystemInformation, Mdv2ConfidenceHigh);
	MDV2_CODE_INTEGRITY_INFORMATION Ci = { sizeof(Ci), 0 }; NTSTATUS CiStatus = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)103, &Ci, sizeof(Ci), NULL);
	auto& CiRecord = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&CiRecord, 9, Mdv2SourceSystemInformation);
	RtlStringCchCopyW(CiRecord.Name, RTL_NUMBER_OF(CiRecord.Name), L"Code Integrity"); CiRecord.Status = CiStatus; CiRecord.Value[0] = Ci.CodeIntegrityOptions;
	const struct { PCWSTR Name; ULONG Mask; } CiFlags[] = {
		{ L"Test signing", 0x2 }, { L"User-mode CI", 0x4 }, { L"CI debug mode", 0x80 },
		{ L"HVCI enabled", 0x400 }, { L"HVCI audit mode", 0x800 }, { L"HVCI strict mode", 0x1000 }, { L"IUM enabled", 0x2000 }
	};
	for (ULONG Index = 0; Index < RTL_NUMBER_OF(CiFlags) && Output->Header.ReturnedCount < Capacity - 2; ++Index) {
		auto& Record = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&Record, 9, Mdv2SourceSystemInformation);
		RtlStringCchCopyW(Record.Name, RTL_NUMBER_OF(Record.Name), CiFlags[Index].Name); Record.Status = CiStatus;
		Record.Value[0] = (Ci.CodeIntegrityOptions & CiFlags[Index].Mask) != 0; Record.Value[1] = CiFlags[Index].Mask;
	}
	MDV2_KERNEL_DEBUGGER_INFORMATION Kd = {}; NTSTATUS KdStatus = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)35, &Kd, sizeof(Kd), NULL);
	auto& KdRecord = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&KdRecord, 9, Mdv2SourceSystemInformation);
	RtlStringCchCopyW(KdRecord.Name, RTL_NUMBER_OF(KdRecord.Name), L"Kernel Debugger"); KdRecord.Status = KdStatus; KdRecord.Value[0] = Kd.Enabled; KdRecord.Value[1] = Kd.NotPresent;
	MDV2_SECURE_BOOT_INFORMATION Sb = {}; NTSTATUS SbStatus = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)145, &Sb, sizeof(Sb), NULL);
	auto& SbRecord = Output->Records[Output->Header.ReturnedCount++]; Mdv2InitRecord(&SbRecord, 9, Mdv2SourceSystemInformation);
	RtlStringCchCopyW(SbRecord.Name, RTL_NUMBER_OF(SbRecord.Name), L"Secure Boot"); SbRecord.Status = SbStatus; SbRecord.Value[0] = Sb.SecureBootEnabled; SbRecord.Value[1] = Sb.SecureBootCapable;
	Output->Header.TotalCount = Output->Header.ReturnedCount; Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) + Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
	return STATUS_SUCCESS;
}

static NTSTATUS Mdv2QueryCapabilities(PMDV2_CAPABILITIES_OUTPUT Output, ULONG OutputLength, PULONG BytesReturned)
{
	if (OutputLength < sizeof(*Output)) return STATUS_BUFFER_TOO_SMALL;
	RtlZeroMemory(Output, sizeof(*Output)); Mdv2InitHeader(&Output->Header, STATUS_SUCCESS, Mdv2SourcePublicApi, Mdv2ConfidenceHigh);
	RTL_OSVERSIONINFOW Version = {}; Version.dwOSVersionInfoSize = sizeof(Version); RtlGetVersion(&Version);
	Output->OsMajor = Version.dwMajorVersion; Output->OsMinor = Version.dwMinorVersion; Output->OsBuild = Version.dwBuildNumber;
#ifdef _M_AMD64
	Output->Architecture = 9;
#elif defined(_M_ARM64)
	Output->Architecture = 12;
#endif
	Output->StableCapabilities = 0x0000000000007FFFull;
	Output->ExperimentalCapabilities = 0x0000000000007800ull;
	Output->Header.RequiredSize = sizeof(*Output); *BytesReturned = sizeof(*Output); return STATUS_SUCCESS;
}

static NTSTATUS Mdv2DispatchInventory(ULONG Ioctl, PVOID InputBuffer, ULONG InputLength,
	PVOID OutputBuffer, ULONG OutputLength, PULONG BytesReturned)
{
	*BytesReturned = 0;
	if (Ioctl == IOCTL_QUERY_CAPABILITIES_V2)
		return Mdv2QueryCapabilities((PMDV2_CAPABILITIES_OUTPUT)OutputBuffer, OutputLength, BytesReturned);
	MDV2_QUERY_INPUT Query = {};
	NTSTATUS Status = Mdv2ValidateRequest((PMDV2_QUERY_INPUT)InputBuffer, InputLength);
	if (!NT_SUCCESS(Status)) return Status;
	RtlCopyMemory(&Query, InputBuffer, sizeof(Query)); Query.Name[RTL_NUMBER_OF(Query.Name) - 1] = L'\0'; Query.Path[RTL_NUMBER_OF(Query.Path) - 1] = L'\0';
	if (OutputLength < FIELD_OFFSET(MDV2_LIST_OUTPUT, Records)) return STATUS_BUFFER_TOO_SMALL;
	RtlZeroMemory(OutputBuffer, OutputLength);
	auto Output = (PMDV2_LIST_OUTPUT)OutputBuffer;
	switch (Ioctl) {
	case IOCTL_QUERY_PROCESS_V2: Status = Mdv2QueryProcess(&Query, Output, OutputLength); break;
	case IOCTL_QUERY_EPROCESS_V2: Status = Mdv2QueryEprocess(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_THREADS_V2: Status = Mdv2EnumerateThreads(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_HANDLES_V2: Status = Mdv2EnumerateHandles(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_MODULES_V2: Status = Query.ProcessId == 0 ? Mdv2EnumerateKernelModules(&Query, Output, OutputLength) : Mdv2EnumerateProcessModules(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_KERNEL_MODULES_V2: Status = Mdv2EnumerateKernelModules(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_BIG_POOL_V2: Status = Mdv2EnumerateBigPool(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_OBJECTS_V2: Status = Mdv2EnumerateObjects(&Query, Output, OutputLength); break;
	case IOCTL_QUERY_DRIVER_V2: Status = Mdv2QueryDriver(&Query, Output, OutputLength); break;
	case IOCTL_QUERY_SECURITY_V2: Status = Mdv2QuerySecurity(Output, OutputLength); break;
	case IOCTL_ENUM_MEMORY_V2: Status = Mdv2EnumerateMemory(&Query, Output, OutputLength); break;
	case IOCTL_QUERY_MEMORY_V2: Status = Mdv2QueryMemory(Output, OutputLength); break;
	case IOCTL_ENUM_MINIFILTERS_V2: Status = Mdv2EnumerateMiniFilters(&Query, Output, OutputLength); break;
	case IOCTL_ENUM_WFP_V2: Status = Mdv2EnumerateNetworkComponents(&Query, Output, OutputLength, TRUE); break;
	case IOCTL_ENUM_NDIS_V2: Status = Mdv2EnumerateNetworkComponents(&Query, Output, OutputLength, FALSE); break;
	default: return STATUS_INVALID_DEVICE_REQUEST;
	}
	if (Output->Header.Size == 0) Mdv2InitHeader(&Output->Header, Status, Mdv2SourceUnknown, Mdv2ConfidenceUnavailable);
	if (!NT_SUCCESS(Status) && Output->Header.Status == STATUS_SUCCESS) Output->Header.Status = Status;
	*BytesReturned = Output->Header.RequiredSize ? min(Output->Header.RequiredSize, OutputLength) : sizeof(MDV2_LIST_HEADER);
	return NT_SUCCESS(Status) ? STATUS_SUCCESS : Status;
}
