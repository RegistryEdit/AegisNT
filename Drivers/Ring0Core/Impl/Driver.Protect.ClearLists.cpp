
static VOID
ClearAllProtectionLists(VOID)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_ProcessListLock, &LockIrql);
	while (!IsListEmpty(&G_ProcessListHead))
	{
		PLIST_ENTRY              Entry = RemoveHeadList(&G_ProcessListHead);
		PPROTECTED_PROCESS_ENTRY PEntry = CONTAINING_RECORD(Entry, PROTECTED_PROCESS_ENTRY, ListEntry);
		ULONG pid = PEntry->ProcessId;
		ExFreePoolWithTag(PEntry, POOL_TAG);
		G_ProcessCount--;
		KeReleaseSpinLock(&G_ProcessListLock, LockIrql);
		RemoveProcessPpl(pid);
		KeAcquireSpinLock(&G_ProcessListLock, &LockIrql);
	}
	KeReleaseSpinLock(&G_ProcessListLock, LockIrql);

	KeAcquireSpinLock(&G_RegistryListLock, &LockIrql);
	while (!IsListEmpty(&G_RegistryListHead))
	{
		PLIST_ENTRY               Entry = RemoveHeadList(&G_RegistryListHead);
		PPROTECTED_REGISTRY_ENTRY REntry = CONTAINING_RECORD(Entry, PROTECTED_REGISTRY_ENTRY, ListEntry);
		ExFreePoolWithTag(REntry, POOL_TAG);
		G_RegistryCount--;
	}
	KeReleaseSpinLock(&G_RegistryListLock, LockIrql);

	KeAcquireSpinLock(&G_FileListLock, &LockIrql);
	while (!IsListEmpty(&G_FileListHead))
	{
		PLIST_ENTRY            Entry = RemoveHeadList(&G_FileListHead);
		PPROTECTED_FILE_ENTRY  FEntry = CONTAINING_RECORD(Entry, PROTECTED_FILE_ENTRY, ListEntry);
		ExFreePoolWithTag(FEntry, POOL_TAG);
		G_FileCount--;
	}
	KeReleaseSpinLock(&G_FileListLock, LockIrql);

	KeAcquireSpinLock(&G_WindowListLock, &LockIrql);
	while (!IsListEmpty(&G_WindowListHead))
	{
		PLIST_ENTRY Entry = RemoveHeadList(&G_WindowListHead);
		PPROTECTED_WINDOW_ENTRY WEntry = CONTAINING_RECORD(Entry, PROTECTED_WINDOW_ENTRY, ListEntry);
		ExFreePoolWithTag(WEntry, POOL_TAG);
		G_WindowCount--;
	}
	KeReleaseSpinLock(&G_WindowListLock, LockIrql);

	KeAcquireSpinLock(&G_InjectionProtectListLock, &LockIrql);
	while (!IsListEmpty(&G_InjectionProtectListHead))
	{
		PLIST_ENTRY Entry = RemoveHeadList(&G_InjectionProtectListHead);
		PPROTECTED_PROCESS_ENTRY PEntry = CONTAINING_RECORD(Entry, PROTECTED_PROCESS_ENTRY, ListEntry);
		ExFreePoolWithTag(PEntry, POOL_TAG);
		G_InjectionProtectCount--;
	}
	KeReleaseSpinLock(&G_InjectionProtectListLock, LockIrql);

	LogMessage("All protection lists cleared.\n");
}