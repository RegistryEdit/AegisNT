
BOOLEAN
IsProcessProtected(
	_In_ HANDLE ProcessId
)
{
	BOOLEAN Result = FALSE;
	ULONG   Pid = HandleToULong(ProcessId);
	KIRQL   LockIrql;

	KeAcquireSpinLock(&G_ProcessListLock, &LockIrql);

	PLIST_ENTRY Current = G_ProcessListHead.Flink;
	while (Current != &G_ProcessListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == Pid)
		{
			Result = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_ProcessListLock, LockIrql);
	return Result;
}

static NTSTATUS
AddProcessToProtectionList(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (G_ProcessCount >= MAX_PROTECTED_PROCESSES)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeAcquireSpinLock(&G_ProcessListLock, &LockIrql);

	PLIST_ENTRY Current = G_ProcessListHead.Flink;
	while (Current != &G_ProcessListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == ProcessId)
		{
			KeReleaseSpinLock(&G_ProcessListLock, LockIrql);
			return STATUS_DUPLICATE_NAME;
		}
	}

	PPROTECTED_PROCESS_ENTRY NewEntry = static_cast<PPROTECTED_PROCESS_ENTRY>(
		AllocPoolZero(sizeof(PROTECTED_PROCESS_ENTRY)));
	if (NewEntry == NULL)
	{
		KeReleaseSpinLock(&G_ProcessListLock, LockIrql);
		return STATUS_NO_MEMORY;
	}

	NewEntry->ProcessId = ProcessId;
	InsertHeadList(&G_ProcessListHead, &NewEntry->ListEntry);
	G_ProcessCount++;

	KeReleaseSpinLock(&G_ProcessListLock, LockIrql);
	LogMessage("Process PID %u added to protection list.\n", ProcessId);
	if (G_PplOffset != 0)
		SetProcessPpl(ProcessId, PsProtectedTypeProtectedLight, PsProtectedSignerWinTcb, FALSE);
	return STATUS_SUCCESS;
}

static NTSTATUS
RemoveProcessFromProtectionList(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_ProcessListLock, &LockIrql);

	BOOLEAN     Found = FALSE;
	PLIST_ENTRY Current = G_ProcessListHead.Flink;
	while (Current != &G_ProcessListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == ProcessId)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			G_ProcessCount--;
			Found = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_ProcessListLock, LockIrql);

	if (Found)
	{
		RemoveProcessPpl(ProcessId);
		LogMessage("Process PID %u removed from protection list.\n", ProcessId);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN
IsInjectionProtected(
	_In_ HANDLE ProcessId
)
{
	BOOLEAN Result = FALSE;
	ULONG   Pid = HandleToULong(ProcessId);
	KIRQL   LockIrql;

	KeAcquireSpinLock(&G_InjectionProtectListLock, &LockIrql);
	PLIST_ENTRY Current = G_InjectionProtectListHead.Flink;
	while (Current != &G_InjectionProtectListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == Pid) { Result = TRUE; break; }
	}
	KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql);
	return Result;
}

static NTSTATUS
AddInjectionProtection(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (G_InjectionProtectCount >= MAX_PROTECTED_PROCESSES)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeAcquireSpinLock(&G_InjectionProtectListLock, &LockIrql);
	PLIST_ENTRY Current = G_InjectionProtectListHead.Flink;
	while (Current != &G_InjectionProtectListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == ProcessId) { KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql); return STATUS_DUPLICATE_NAME; }
	}

	PPROTECTED_PROCESS_ENTRY NewEntry = (PPROTECTED_PROCESS_ENTRY)AllocPoolZero(sizeof(PROTECTED_PROCESS_ENTRY));
	if (NewEntry == NULL) { KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql); return STATUS_NO_MEMORY; }
	NewEntry->ProcessId = ProcessId;
	InsertHeadList(&G_InjectionProtectListHead, &NewEntry->ListEntry);
	G_InjectionProtectCount++;
	KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql);
	LogMessage("PID %u added to injection protection (no PPL).\n", ProcessId);
	return STATUS_SUCCESS;
}

static NTSTATUS
RemoveInjectionProtection(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_InjectionProtectListLock, &LockIrql);
	BOOLEAN Found = FALSE;
	PLIST_ENTRY Current = G_InjectionProtectListHead.Flink;
	while (Current != &G_InjectionProtectListHead)
	{
		PPROTECTED_PROCESS_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_PROCESS_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->ProcessId == ProcessId)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			G_InjectionProtectCount--;
			Found = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql);
	if (Found) { LogMessage("PID %u removed from injection protection.\n", ProcessId); return STATUS_SUCCESS; }
	return STATUS_NOT_FOUND;
}