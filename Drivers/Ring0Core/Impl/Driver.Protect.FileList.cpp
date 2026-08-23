
BOOLEAN
IsFilePathProtected(
	_In_ PUNICODE_STRING FilePath
)
{
	if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
		return FALSE;

	BOOLEAN Result = FALSE;
	KIRQL   LockIrql;

	KeAcquireSpinLock(&G_FileListLock, &LockIrql);

	PLIST_ENTRY Current = G_FileListHead.Flink;
	while (Current != &G_FileListHead)
	{
		PPROTECTED_FILE_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_FILE_ENTRY, ListEntry);
		Current = Current->Flink;

		UNICODE_STRING StoredPath;
		RtlInitUnicodeString(&StoredPath, Entry->FilePath);

		UNICODE_STRING Prefix = *FilePath;
		if (Prefix.Length > StoredPath.Length)
			Prefix.Length = StoredPath.Length;
		if (Prefix.Length == StoredPath.Length &&
			RtlEqualUnicodeString(&Prefix, &StoredPath, TRUE))
		{
			Result = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_FileListLock, LockIrql);
	return Result;
}

static NTSTATUS
AddFilePathToProtectionList(
	_In_ PCWSTR FilePath
)
{
	KIRQL LockIrql;

	if (G_FileCount >= MAX_PROTECTED_FILES)
		return STATUS_INSUFFICIENT_RESOURCES;

	SIZE_T PathLen = wcsnlen_s(FilePath, 260);
	if (PathLen == 0 || PathLen >= 260)
		return STATUS_BUFFER_OVERFLOW;

	KeAcquireSpinLock(&G_FileListLock, &LockIrql);

	PLIST_ENTRY Current = G_FileListHead.Flink;
	while (Current != &G_FileListHead)
	{
		PPROTECTED_FILE_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_FILE_ENTRY, ListEntry);
		Current = Current->Flink;
		if (_wcsicmp(Entry->FilePath, FilePath) == 0)
		{
			KeReleaseSpinLock(&G_FileListLock, LockIrql);
			return STATUS_DUPLICATE_NAME;
		}
	}

	PPROTECTED_FILE_ENTRY NewEntry = static_cast<PPROTECTED_FILE_ENTRY>(
		AllocPoolZero(sizeof(PROTECTED_FILE_ENTRY)));
	if (NewEntry == NULL)
	{
		KeReleaseSpinLock(&G_FileListLock, LockIrql);
		return STATUS_NO_MEMORY;
	}

	wcscpy_s(NewEntry->FilePath, 260, FilePath);
	InsertHeadList(&G_FileListHead, &NewEntry->ListEntry);
	G_FileCount++;

	KeReleaseSpinLock(&G_FileListLock, LockIrql);
	LogMessage("File path '%ws' added to protection list.\n", FilePath);
	return STATUS_SUCCESS;
}

static NTSTATUS
RemoveFilePathFromProtectionList(
	_In_ PCWSTR FilePath
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_FileListLock, &LockIrql);

	BOOLEAN     Found = FALSE;
	PLIST_ENTRY Current = G_FileListHead.Flink;
	while (Current != &G_FileListHead)
	{
		PPROTECTED_FILE_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_FILE_ENTRY, ListEntry);
		Current = Current->Flink;
		if (_wcsicmp(Entry->FilePath, FilePath) == 0)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			G_FileCount--;
			Found = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_FileListLock, LockIrql);

	if (Found)
	{
		LogMessage("File path '%ws' removed from protection list.\n", FilePath);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}