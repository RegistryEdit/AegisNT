
static PVOID
FindKernel32BaseInProcess(
	_In_ PEPROCESS Process
)
{
	KAPC_STATE ApcState;
	PVOID Kernel32Base = NULL;

	KeStackAttachProcess(Process, &ApcState);

	__try
	{
		PROCESS_BASIC_INFORMATION Pbi;
		NTSTATUS Status = ZwQueryInformationProcess(
			ZwCurrentProcess(),
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (!NT_SUCCESS(Status) || Pbi.PebBaseAddress == NULL)
			__leave;

		PVOID LdrPtr = NULL;
		Status = SafeCopyMemory(&LdrPtr, (PUCHAR)Pbi.PebBaseAddress + 0x018, sizeof(PVOID));
		if (!NT_SUCCESS(Status) || LdrPtr == NULL)
			__leave;

		LIST_ENTRY ListHead;
		Status = SafeCopyMemory(&ListHead, (PUCHAR)LdrPtr + 0x010, sizeof(LIST_ENTRY));
		if (!NT_SUCCESS(Status))
			__leave;

		PLIST_ENTRY Current = ListHead.Flink;
		PLIST_ENTRY HeadPtr = (PLIST_ENTRY)((PUCHAR)LdrPtr + 0x010);

		UNICODE_STRING TargetName;
		RtlInitUnicodeString(&TargetName, L"kernel32.dll");

		for (int i = 0; i < 64 && Current != HeadPtr; i++)
		{
			PVOID DllBase = NULL;
			UNICODE_STRING ModName;
			LARGE_INTEGER ModSizeLI;

			if (!NT_SUCCESS(SafeCopyMemory(&DllBase, (PUCHAR)Current + 0x030, sizeof(PVOID))))
				break;
			if (!NT_SUCCESS(SafeCopyMemory(&ModSizeLI, (PUCHAR)Current + 0x040, sizeof(LARGE_INTEGER))))
				break;
			if (!NT_SUCCESS(SafeCopyMemory(&ModName, (PUCHAR)Current + 0x058, sizeof(UNICODE_STRING))))
				break;

			if (ModName.Buffer != NULL && ModName.Length >= TargetName.Length &&
				ModSizeLI.QuadPart != 0)
			{
				WCHAR Buf[64];
				ULONG CopyLen = ModName.Length;
				if (CopyLen > sizeof(Buf) - sizeof(WCHAR))
					CopyLen = sizeof(Buf) - sizeof(WCHAR);
				if (NT_SUCCESS(SafeCopyMemory(Buf, ModName.Buffer, CopyLen)))
				{
					Buf[CopyLen / sizeof(WCHAR)] = L'\0';
					if (_wcsicmp(Buf, L"kernel32.dll") == 0)
					{
						Kernel32Base = DllBase;
						break;
					}
				}
			}

			LIST_ENTRY Next;
			if (!NT_SUCCESS(SafeCopyMemory(&Next, Current, sizeof(LIST_ENTRY))))
				break;
			Current = Next.Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Kernel32Base = NULL;
	}

	KeUnstackDetachProcess(&ApcState);
	return Kernel32Base;
}

static PVOID
FindKernel32BaseFromAnyProcess(VOID)
{
	static const ULONG CandidatePids[] = { 4, 0 };

	for (ULONG i = 0; i < RTL_NUMBER_OF(CandidatePids); i++)
	{
		ULONG Pid = CandidatePids[i];
		if (Pid == 0)
		{
			Pid = FindProcessPidByName(L"explorer.exe");
			if (Pid == 0)
				Pid = FindProcessPidByName(L"svchost.exe");
			if (Pid == 0)
				continue;
		}

		PEPROCESS Process = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Pid), &Process)))
			continue;

		PVOID Base = FindKernel32BaseInProcess(Process);
		ObfDereferenceObject(Process);
		if (Base != NULL)
			return Base;
	}

	return NULL;
}

static PVOID
FindExportByName(
	_In_ PVOID ModuleBase,
	_In_ PCSTR ExportName
)
{
	if (ModuleBase == NULL || ExportName == NULL)
		return NULL;

	__try
	{
		PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ModuleBase;
		if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + Dos->e_lfanew);
		if (Nt->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		IMAGE_DATA_DIRECTORY ExpDir =
			Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ExpDir.VirtualAddress == 0 || ExpDir.Size == 0)
			return NULL;

		PIMAGE_EXPORT_DIRECTORY Exp =
			(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ExpDir.VirtualAddress);
		PULONG Names = (PULONG)((PUCHAR)ModuleBase + Exp->AddressOfNames);
		PUSHORT Ords = (PUSHORT)((PUCHAR)ModuleBase + Exp->AddressOfNameOrdinals);
		PULONG Funcs = (PULONG)((PUCHAR)ModuleBase + Exp->AddressOfFunctions);

		SIZE_T NameLen = strlen(ExportName);
		for (ULONG i = 0; i < Exp->NumberOfNames; i++)
		{
			PCSTR Name = (PCSTR)((PUCHAR)ModuleBase + Names[i]);
			if (RtlCompareMemory(Name, ExportName, NameLen) == NameLen &&
				Name[NameLen] == '\0')
			{
				ULONG Rva = Funcs[Ords[i]];
				if (Rva >= ExpDir.VirtualAddress &&
					Rva < ExpDir.VirtualAddress + ExpDir.Size)
					return NULL;
				return (PVOID)((PUCHAR)ModuleBase + Rva);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

static PVOID
ResolveLoadLibraryW(VOID)
{
	static PVOID CachedLoadLibraryW = NULL;

	if (CachedLoadLibraryW != NULL)
		return CachedLoadLibraryW;

	PVOID Kernel32Base = FindKernel32BaseFromAnyProcess();
	if (Kernel32Base == NULL)
	{
		LogMessage("DllInjectApc: could not locate kernel32.dll base.\n");
		return NULL;
	}

	PVOID LoadLibraryAddr = FindExportByName(Kernel32Base, "LoadLibraryW");
	if (LoadLibraryAddr == NULL)
	{
		LogMessage("DllInjectApc: LoadLibraryW not found in kernel32.dll.\n");
		return NULL;
	}

	CachedLoadLibraryW = LoadLibraryAddr;
	LogMessage("DllInjectApc: resolved LoadLibraryW at %p.\n", LoadLibraryAddr);
	return LoadLibraryAddr;
}

static VOID
DllInjectApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);

	if (SystemArgument1 && *SystemArgument1)
		ExFreePoolWithTag(*SystemArgument1, POOL_TAG);
	if (SystemArgument2 && *SystemArgument2)
		ExFreePoolWithTag(*SystemArgument2, POOL_TAG);

	ExFreePoolWithTag(Apc, POOL_TAG);
}

NTSTATUS
DllInjectApc(
	_In_ ULONG  ProcessId,
	_In_ PCWSTR DllPath
)
{
	if (DllPath == NULL || DllPath[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	PVOID LoadLibraryW = ResolveLoadLibraryW();
	if (LoadLibraryW == NULL)
		return STATUS_PROCEDURE_NOT_FOUND;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DllInjectApc: PID %u not found.\n", ProcessId);
		return Status;
	}

	SIZE_T PathByteLen = (wcslen(DllPath) + 1) * sizeof(WCHAR);
	SIZE_T AllocSize = PathByteLen;
	PVOID RemotePath = NULL;
	KAPC_STATE ApcState;

	KeStackAttachProcess(Process, &ApcState);

	if (G_pZwAllocateVirtualMemory == NULL)
	{
		UNICODE_STRING Rtn;
		RtlInitUnicodeString(&Rtn, L"ZwAllocateVirtualMemory");
		G_pZwAllocateVirtualMemory = (PZwAllocateVirtualMemory_t)MmGetSystemRoutineAddress(&Rtn);
	}

	if (G_pZwAllocateVirtualMemory == NULL)
	{
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectApc: ZwAllocateVirtualMemory unavailable.\n");
		return STATUS_NOT_SUPPORTED;
	}

	Status = G_pZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&RemotePath,
		0,
		&AllocSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!NT_SUCCESS(Status))
	{
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectApc: memory allocation failed 0x%08X.\n", Status);
		return Status;
	}

	__try
	{
		RtlCopyMemory(RemotePath, DllPath, PathByteLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
	}

	if (!NT_SUCCESS(Status))
	{
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		return Status;
	}

	PETHREAD TargetThread = NULL;
	QueueApcFindThread(Process, &TargetThread);

	if (TargetThread == NULL)
	{
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectApc: no thread found for PID %u.\n", ProcessId);
		return STATUS_NOT_FOUND;
	}

	PKAPC Apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG);
	if (Apc == NULL)
	{
		ObfDereferenceObject(TargetThread);
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(
		Apc,
		(PKTHREAD)TargetThread,
		OriginalApcEnvironment,
		DllInjectApcKernelRoutine,
		NULL,
		(PKNORMAL_ROUTINE)LoadLibraryW,
		UserMode,
		RemotePath);

	BOOLEAN Inserted = KeInsertQueueApc(Apc, NULL, NULL, 0);

	if (!Inserted)
	{
		ExFreePoolWithTag(Apc, POOL_TAG);
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		ObfDereferenceObject(TargetThread);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectApc: KeInsertQueueApc failed.\n");
		return STATUS_UNSUCCESSFUL;
	}

	LogMessage("DllInjectApc: APC DLL injection queued to PID %u, thread %p.\n",
		ProcessId, PsGetThreadId(TargetThread));

	ObfDereferenceObject(TargetThread);
	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(Process);
	return STATUS_SUCCESS;
}
