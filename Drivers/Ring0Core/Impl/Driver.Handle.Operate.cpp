
NTSTATUS
ForceCloseHandle(
	_In_ ULONG ProcessId,
	_In_ ULONG HandleValue
)
{
	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("ForceCloseHandle: PID %u not found.\n", ProcessId);
		return Status;
	}

	HANDLE TargetHandle = ULongToHandle(HandleValue);

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	Status = ZwClose(TargetHandle);

	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(Process);

	if (NT_SUCCESS(Status))
		LogMessage("ForceCloseHandle: closed handle 0x%X in PID %u.\n", HandleValue, ProcessId);
	else
		LogMessage("ForceCloseHandle: ZwClose failed 0x%08X.\n", Status);

	return Status;
}

NTSTATUS
DowngradeHandle(
	_Inout_ PHANDLE_DOWNGRADE_INPUT Input
)
{
	ULONG ProcessId = Input->ProcessId;
	ULONG HandleValue = Input->HandleValue;
	ACCESS_MASK NewAccess = Input->NewAccess;

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DowngradeHandle: PID %u not found.\n", ProcessId);
		return Status;
	}

	HANDLE OldHandle = ULongToHandle(HandleValue);
	PVOID   Object    = NULL;

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	Status = ObReferenceObjectByHandle(OldHandle, 0, NULL, UserMode, &Object, NULL);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DowngradeHandle: ObReferenceObjectByHandle failed 0x%08X.\n", Status);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		return Status;
	}

	ZwClose(OldHandle);

	HANDLE NewHandle = NULL;
	Status = ObOpenObjectByPointer(Object, 0, NULL, NewAccess, NULL, KernelMode, &NewHandle);

	ObfDereferenceObject(Object);
	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(Process);

	if (NT_SUCCESS(Status))
	{
		Input->NewHandleValue = HandleToULong(NewHandle);
		LogMessage("DowngradeHandle: PID %u handle 0x%X -> 0x%X (access 0x%08X).\n",
			ProcessId, HandleValue, Input->NewHandleValue, (ULONG)NewAccess);
	}
	else
	{
		LogMessage("DowngradeHandle: ObOpenObjectByPointer failed 0x%08X.\n", Status);
	}

	return Status;
}

NTSTATUS
DuplicateAndDowngradeHandle(
	_In_  ULONG                      SourceProcessId,
	_In_  ULONG                      SourceHandle,
	_In_  ULONG                      TargetProcessId,
	_In_  ACCESS_MASK                NewAccess,
	_Out_ PHANDLE_DUP_DOWNGRADE_OUTPUT Output
)
{
	RtlZeroMemory(Output, sizeof(*Output));
	Output->NewHandle = 0;
	Output->Status = STATUS_UNSUCCESSFUL;

	if (SourceHandle == 0)
		return STATUS_INVALID_HANDLE;

	PEPROCESS SourceProcess = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(SourceProcessId), &SourceProcess);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DupDowngrade: source PID %u not found.\n", SourceProcessId);
		Output->Status = Status;
		return Status;
	}

	HANDLE hSrc = ULongToHandle(SourceHandle);
	PVOID  Object = NULL;

	KAPC_STATE ApcState;
	KeStackAttachProcess(SourceProcess, &ApcState);

	Status = ObReferenceObjectByHandle(hSrc, 0, NULL, UserMode, &Object, NULL);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DupDowngrade: ObReferenceObjectByHandle failed 0x%08X.\n", Status);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(SourceProcess);
		Output->Status = Status;
		return Status;
	}

	ZwClose(hSrc);

	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(SourceProcess);

	PEPROCESS TargetProcess = NULL;
	Status = PsLookupProcessByProcessId(ULongToHandle(TargetProcessId), &TargetProcess);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("DupDowngrade: target PID %u not found.\n", TargetProcessId);
		ObfDereferenceObject(Object);
		Output->Status = Status;
		return Status;
	}

	HANDLE hNew = NULL;
	KeStackAttachProcess(TargetProcess, &ApcState);

	Status = ObOpenObjectByPointer(
		Object,
		0,
		NULL,
		NewAccess,
		NULL,
		KernelMode,
		&hNew);

	KeUnstackDetachProcess(&ApcState);

	if (NT_SUCCESS(Status))
	{
		Output->NewHandle = (ULONG_PTR)hNew;
		LogMessage("DupDowngrade: src PID %u handle 0x%X -> dst PID %u handle 0x%X (access 0x%08X).\n",
			SourceProcessId, SourceHandle, TargetProcessId, HandleToULong(hNew), (ULONG)NewAccess);
	}
	else
	{
		LogMessage("DupDowngrade: ObOpenObjectByPointer in target failed 0x%08X.\n", Status);
	}

	ObfDereferenceObject(Object);
	ObfDereferenceObject(TargetProcess);
	Output->Status = Status;
	return Status;
}
