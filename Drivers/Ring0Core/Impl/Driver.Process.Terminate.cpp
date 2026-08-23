
NTSTATUS
ForceTerminateProcess(
	_In_ ULONG ProcessId
)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;

	UNICODE_STRING RoutineName;
	RtlInitUnicodeString(&RoutineName, L"PspTerminateProcess");
	PVOID PspTerminateProcessAddr = MmGetSystemRoutineAddress(&RoutineName);

	if (PspTerminateProcessAddr != NULL)
	{
		Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
		if (NT_SUCCESS(Status))
		{
			typedef NTSTATUS(*PspTerminateProcess_t)(PEPROCESS, NTSTATUS);
			PspTerminateProcess_t PspTerminateProcessFn =
				reinterpret_cast<PspTerminateProcess_t>(PspTerminateProcessAddr);

			LogMessage("Terminating PID %u via PspTerminateProcess.\n", ProcessId);
			Status = PspTerminateProcessFn(Process, STATUS_SUCCESS);
			ObfDereferenceObject(Process);
			return Status;
		}
	}

	HANDLE ProcessHandle = NULL;
	CLIENT_ID ClientId = { ULongToHandle(ProcessId), NULL };
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, OBJ_KERNEL_HANDLE);

	Status = ZwOpenProcess(
		&ProcessHandle,
		PROCESS_TERMINATE,
		&ObjectAttributes,
		&ClientId);

	if (NT_SUCCESS(Status))
	{
		LogMessage("Terminating PID %u via ZwTerminateProcess.\n", ProcessId);
		Status = ZwTerminateProcess(ProcessHandle, STATUS_SUCCESS);
		ZwClose(ProcessHandle);
		return Status;
	}

	Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (NT_SUCCESS(Status))
	{
		LogMessage("Terminating PID %u via EPROCESS zeroing.\n", ProcessId);

#ifdef _M_AMD64
		PCHAR ProcessBase = reinterpret_cast<PCHAR>(Process) + EPROCESS_SCAN_START;
		CONST ULONG EndOffset = ALIGN_UP_BY(Process, PAGE_SIZE) -
			reinterpret_cast<ULONG_PTR>(Process);
		for (ULONG i = 0; i < EndOffset - EPROCESS_SCAN_START - sizeof(ULONG); i++)
		{
			if (*reinterpret_cast<PULONG>(ProcessBase + i) ==
				HandleToULong(PsGetProcessId(Process)))
			{
				RtlZeroMemory(ProcessBase + i, sizeof(ULONG));
				break;
			}
		}
#endif

		ObfDereferenceObject(Process);
		return STATUS_SUCCESS;
	}

	LogMessage("ForceTerminateProcess: all methods failed for PID %u (0x%08X).\n",
		ProcessId, Status);
	return Status;
}
