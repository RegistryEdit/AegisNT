
NTSTATUS
GetCmdLine(
	_In_ PCOMMAND_LINE_INPUT Input,
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (Input == NULL || Input->ProcessId == 0 || Input->ProcessId == 4)
		return STATUS_INVALID_PARAMETER;

	if (OutputBuffer == NULL || OutputLength < sizeof(WCHAR))
		return STATUS_BUFFER_TOO_SMALL;

	PWCHAR Buf = (PWCHAR)OutputBuffer;
	Buf[0] = L'\0';

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Input->ProcessId), &Process);
	if (!NT_SUCCESS(Status))
		return Status;

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	__try
	{
		PROCESS_BASIC_INFORMATION Pbi;
		Status = ZwQueryInformationProcess(ZwCurrentProcess(),
			ProcessBasicInformation, &Pbi, sizeof(Pbi), NULL);
		if (!NT_SUCCESS(Status) || Pbi.PebBaseAddress == NULL)
			__leave;

		PVOID pParamsPtr = NULL;
		PVOID PEB_ProcessParams = (PVOID)((ULONG_PTR)Pbi.PebBaseAddress + 0x20);
		Status = SafeCopyMemory(&pParamsPtr, PEB_ProcessParams, sizeof(PVOID));
		if (!NT_SUCCESS(Status) || pParamsPtr == NULL)
			__leave;

		UNICODE_STRING CmdLine;
		PVOID CmdLineAddr = (PVOID)((ULONG_PTR)pParamsPtr + 0x70);
		Status = SafeCopyMemory(&CmdLine, CmdLineAddr, sizeof(UNICODE_STRING));
		if (!NT_SUCCESS(Status) || CmdLine.Buffer == NULL || CmdLine.Length == 0)
			__leave;

		ULONG CopyLen = CmdLine.Length;
		if (CopyLen > OutputLength - sizeof(WCHAR))
			CopyLen = OutputLength - sizeof(WCHAR);

		Status = SafeCopyMemory(Buf, CmdLine.Buffer, CopyLen);
		if (NT_SUCCESS(Status))
		{
			Buf[CopyLen / sizeof(WCHAR)] = L'\0';
			*BytesReturned = CopyLen + sizeof(WCHAR);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(Process);
	return Status;
}
