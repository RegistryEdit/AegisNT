
static PVOID
ResolveLoadLibraryWForThreadInject(VOID)
{
	PVOID Kernel32Base = FindKernel32BaseInProcess(PsGetCurrentProcess());
	if (Kernel32Base == NULL)
	{
		Kernel32Base = FindKernel32BaseFromAnyProcess();
	}
	if (Kernel32Base == NULL)
	{
		LogMessage("DllInjectThread: could not locate kernel32.dll base.\n");
		return NULL;
	}

	PVOID LoadLibraryAddr = FindExportByName(Kernel32Base, "LoadLibraryW");
	if (LoadLibraryAddr == NULL)
	{
		LogMessage("DllInjectThread: LoadLibraryW not found in kernel32.dll.\n");
		return NULL;
	}

	LogMessage("DllInjectThread: resolved LoadLibraryW at %p.\n", LoadLibraryAddr);
	return LoadLibraryAddr;
}

static NTSTATUS
CreateUserThreadInTarget(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_ PVOID Argument
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
		return G_pZwCreateThreadEx(NULL,
			MAXIMUM_ALLOWED, NULL, ProcessHandle,
			StartRoutine, Argument, 0, 0, 0, 0, NULL);
	}

	if (G_pRtlCreateUserThread != NULL)
	{
		return G_pRtlCreateUserThread(ProcessHandle,
			NULL, FALSE, 0, NULL, NULL,
			StartRoutine, Argument, NULL, NULL);
	}

	return STATUS_PROCEDURE_NOT_FOUND;
}

NTSTATUS
DllInjectThread(
	_In_ ULONG  ProcessId,
	_In_ PCWSTR DllPath
)
{
	if (DllPath == NULL || DllPath[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	PVOID LoadLibraryW = ResolveLoadLibraryWForThreadInject();
	if (LoadLibraryW == NULL)
		return STATUS_PROCEDURE_NOT_FOUND;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DllInjectThread: PID %u not found.\n", ProcessId);
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
		LogMessage("DllInjectThread: ZwAllocateVirtualMemory unavailable.\n");
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
		LogMessage("DllInjectThread: memory allocation failed 0x%08X.\n", Status);
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

	HANDLE TargetProcessHandle = NULL;
	Status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
		PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		KernelMode,
		&TargetProcessHandle);

	if (!NT_SUCCESS(Status))
	{
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectThread: ObOpenObjectByPointer failed 0x%08X.\n", Status);
		return Status;
	}

	Status = CreateUserThreadInTarget(TargetProcessHandle, LoadLibraryW, RemotePath);

	KeUnstackDetachProcess(&ApcState);

	if (!NT_SUCCESS(Status))
	{
		KeStackAttachProcess(Process, &ApcState);
		AllocSize = 0;
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemotePath, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		ZwClose(TargetProcessHandle);
		ObfDereferenceObject(Process);
		LogMessage("DllInjectThread: CreateUserThreadInTarget failed 0x%08X.\n", Status);
		return Status;
	}

	LogMessage("DllInjectThread: remote thread created in PID %u, entry %p, arg %p.\n",
		ProcessId, LoadLibraryW, RemotePath);

	ZwClose(TargetProcessHandle);
	ObfDereferenceObject(Process);
	return STATUS_SUCCESS;
}
