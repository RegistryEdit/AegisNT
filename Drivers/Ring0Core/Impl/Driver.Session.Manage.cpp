
NTSTATUS
SessionOperation(
	_In_ PSESSION_OPERATION_INPUT Input,
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (Input == NULL) return STATUS_INVALID_PARAMETER;

	switch (Input->Operation)
	{
	case 0: 
	{
		ULONG BufSize = 0;
		NTSTATUS Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &BufSize);
		if (Status != STATUS_INFO_LENGTH_MISMATCH) return Status;

		PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
		if (SysBuf == NULL) return STATUS_INSUFFICIENT_RESOURCES;

		Status = ZwQuerySystemInformation(SystemProcessInformation, SysBuf, BufSize * 2, NULL);
		if (!NT_SUCCESS(Status)) { ExFreePoolWithTag(SysBuf, POOL_TAG); return Status; }

		ULONG SeenSessions[64] = { 0 };
		ULONG ProcessCounts[64] = { 0 };
		ULONG SeenCount = 0;

		PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
		while (TRUE)
		{
			ULONG Sid = Entry->SessionId;
			BOOLEAN Found = FALSE;
			for (ULONG i = 0; i < SeenCount; i++)
			{
				if (SeenSessions[i] == Sid) { ProcessCounts[i]++; Found = TRUE; break; }
			}
			if (!Found && SeenCount < 64)
			{
				SeenSessions[SeenCount] = Sid;
				ProcessCounts[SeenCount] = 1;
				SeenCount++;
			}
			if (Entry->NextEntryOffset == 0) break;
			Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
		}
		ExFreePoolWithTag(SysBuf, POOL_TAG);

		if (OutputBuffer && OutputLength >= sizeof(ULONG) + SeenCount * (sizeof(ULONG) * 3 + 64))
		{
			PULONG Count = (PULONG)OutputBuffer;
			*Count = SeenCount;
			PUCHAR Data = (PUCHAR)(Count + 1);
			for (ULONG i = 0; i < SeenCount; i++)
			{
				*(PULONG)Data = SeenSessions[i]; Data += 4;
				*(PULONG)Data = (SeenSessions[i] == 0) ? 0 : 1; Data += 4;
				*(PULONG)Data = ProcessCounts[i]; Data += 4;
				RtlStringCbPrintfW((PWCHAR)Data, 64, L"Session%u", SeenSessions[i]);
				Data += 64;
			}
			*BytesReturned = (ULONG)(Data - (PUCHAR)OutputBuffer);
		}
		return STATUS_SUCCESS;
	}

	case 1: 
	{
		ULONG BufSize = 0;
		NTSTATUS Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &BufSize);
		if (Status != STATUS_INFO_LENGTH_MISMATCH) return Status;

		PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
		if (SysBuf == NULL) return STATUS_INSUFFICIENT_RESOURCES;

		Status = ZwQuerySystemInformation(SystemProcessInformation, SysBuf, BufSize * 2, NULL);
		if (!NT_SUCCESS(Status)) { ExFreePoolWithTag(SysBuf, POOL_TAG); return Status; }

		PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
		while (TRUE)
		{
			if (Entry->SessionId == Input->SessionId)
			{
				ULONG Pid = (ULONG)(ULONG_PTR)Entry->UniqueProcessId;
				if (Pid > 4)
				{
					PEPROCESS Process = NULL;
					if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Pid), &Process)))
					{
						ZwTerminateProcess(NULL, STATUS_SUCCESS);
						ObfDereferenceObject(Process);
					}
				}
			}
			if (Entry->NextEntryOffset == 0) break;
			Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
		}
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		LogMessage("SessionOp: logged off session %u.\n", Input->SessionId);
		return STATUS_SUCCESS;
	}
	}
	return STATUS_INVALID_PARAMETER;
}
