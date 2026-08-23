
NTSTATUS
EnumerateProcesses(
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_  ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;

	ULONG LocalCount = 0;
	PROCESS_ENUM_ENTRY* LocalEntries = NULL;

	{
		ULONG LocalMax = 1024;
		LocalEntries = (PROCESS_ENUM_ENTRY*)ExAllocatePool2(
			POOL_FLAG_NON_PAGED, LocalMax * sizeof(PROCESS_ENUM_ENTRY), POOL_TAG);
		if (LocalEntries == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;
		RtlZeroMemory(LocalEntries, LocalMax * sizeof(PROCESS_ENUM_ENTRY));
	}

	ULONG BufSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		SystemProcessInformation, NULL, 0, &BufSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePoolWithTag(LocalEntries, POOL_TAG);
		return Status;
	}

	PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
	if (SysBuf == NULL)
	{
		ExFreePoolWithTag(LocalEntries, POOL_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = ZwQuerySystemInformation(
		SystemProcessInformation, SysBuf, BufSize * 2, NULL);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		ExFreePoolWithTag(LocalEntries, POOL_TAG);
		return Status;
	}

	PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
	while (TRUE)
	{
		if (LocalCount >= 1024)
			break;

		PROCESS_ENUM_ENTRY* Info = &LocalEntries[LocalCount];
		Info->ProcessId   = (ULONG)(ULONG_PTR)Entry->UniqueProcessId;
		Info->ParentPid   = (ULONG)(ULONG_PTR)Entry->InheritedFromUniqueProcessId;
		Info->ThreadCount = Entry->NumberOfThreads;
		Info->SessionId   = 0;

		if (Entry->ImageName.Length > 0 && Entry->ImageName.Buffer != NULL)
		{
			ULONG NameLen = Entry->ImageName.Length / sizeof(WCHAR);
			if (NameLen > 15) NameLen = 15;
			RtlCopyMemory(Info->ImageName, Entry->ImageName.Buffer, NameLen * sizeof(WCHAR));
			Info->ImageName[NameLen] = L'\0';
		}
		else
		{
			Info->ImageName[0] = L'\0';
		}

		{
			PEPROCESS Process = NULL;
			NTSTATUS S = PsLookupProcessByProcessId(
				ULongToHandle(Info->ProcessId), &Process);
			if (NT_SUCCESS(S))
			{
				Info->ObjectAddress = (ULONG_PTR)Process;
				Info->SessionId = QueryProcessSessionId(Process);

				if (G_PplOffset != 0)
				{
					PPS_PROTECTION Prot = (PPS_PROTECTION)
						((PUCHAR)Process + G_PplOffset);
					Info->PplRawLevel    = Prot->Level;
					Info->IsPplProtected = (Prot->Level > 0);
				}

				{
					HANDLE hProc = NULL;
					S = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
						PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProc);
					if (NT_SUCCESS(S))
					{
						ULONG BreakVal = 0;
						NTSTATUS S2 = ZwQueryInformationProcess(
							hProc, ProcessBreakOnTermination,
							&BreakVal, sizeof(ULONG), NULL);
						if (NT_SUCCESS(S2))
							Info->IsCritical = (BreakVal != 0);
						ZwClose(hProc);
					}
				}

				if (G_ActiveLinksOffsetFound)
				{
					PLIST_ENTRY Link = (PLIST_ENTRY)
						((PUCHAR)Process + G_ActiveProcessLinksOffset);
					if (Link->Flink == Link && Link->Blink == Link)
						Info->IsHidden = TRUE;
				}

				ObfDereferenceObject(Process);
			}
		}

		LocalCount++;

		if (Entry->NextEntryOffset == 0)
			break;
		Entry = (PSYSTEM_PROCESS_INFORMATION)
			((PUCHAR)Entry + Entry->NextEntryOffset);
	}

	ExFreePoolWithTag(SysBuf, POOL_TAG);

	if (OutputLength >= sizeof(ULONG))
	{
		PPROCESS_ENUM_OUTPUT Out = (PPROCESS_ENUM_OUTPUT)OutputBuffer;
		Out->Count = LocalCount;

		if (OutputLength >= sizeof(PROCESS_ENUM_OUTPUT))
		{
			ULONG MaxEntries = (OutputLength - FIELD_OFFSET(PROCESS_ENUM_OUTPUT, Entries))
				/ sizeof(PROCESS_ENUM_ENTRY);
			ULONG CopyCount = (LocalCount < MaxEntries) ? LocalCount : MaxEntries;

			RtlCopyMemory(Out->Entries, LocalEntries, CopyCount * sizeof(PROCESS_ENUM_ENTRY));
			*BytesReturned = FIELD_OFFSET(PROCESS_ENUM_OUTPUT, Entries)
				+ CopyCount * sizeof(PROCESS_ENUM_ENTRY);
		}
		else
		{
			*BytesReturned = sizeof(ULONG);
		}
	}

	ExFreePoolWithTag(LocalEntries, POOL_TAG);
	return (*BytesReturned > 0) ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}
