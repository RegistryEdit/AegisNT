
NTSTATUS
RemoveAllFilters(
	VOID
)
{
	KIRQL LockIrql;

	if (InterlockedExchange(&G_RemoveFiltersInProgress, 1) != 0)
	{
		LogMessage("RemoveAllFilters: already in progress.\n");
		return STATUS_DEVICE_BUSY;
	}

	KeAcquireSpinLock(&G_FileListLock, &LockIrql);
	while (!IsListEmpty(&G_FileListHead))
	{
		PLIST_ENTRY             Entry = RemoveHeadList(&G_FileListHead);
		PPROTECTED_FILE_ENTRY   FEntry = CONTAINING_RECORD(Entry, PROTECTED_FILE_ENTRY, ListEntry);
		ExFreePoolWithTag(FEntry, POOL_TAG);
		G_FileCount--;
	}
	InitializeListHead(&G_FileListHead);
	KeReleaseSpinLock(&G_FileListLock, LockIrql);
	G_FltFilterActive = FALSE;

	LogMessage("File protection removed.\n");

	InterlockedExchange(&G_RemoveFiltersInProgress, 0);
	return STATUS_SUCCESS;
}