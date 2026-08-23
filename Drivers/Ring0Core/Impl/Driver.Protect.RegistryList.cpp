
static BOOLEAN
IsRegistryObjectProtected(
	_In_ PVOID KeyObject
)
{
	if (KeyObject == NULL)
		return FALSE;

	static PCmCallbackGetKeyObjectIDEx     pfnGetIdEx  = NULL;
	static PCmCallbackGetKeyObjectID       pfnGetId    = NULL;
	static PCmCallbackReleaseKeyObjectIDEx pfnRelease  = NULL;
	static BOOLEAN s_InitDone = FALSE;

	if (!s_InitDone)
	{
		s_InitDone = TRUE;
		UNICODE_STRING rn;

		RtlInitUnicodeString(&rn, L"CmCallbackGetKeyObjectIDEx");
		pfnGetIdEx = (PCmCallbackGetKeyObjectIDEx)MmGetSystemRoutineAddress(&rn);

		RtlInitUnicodeString(&rn, L"CmCallbackGetKeyObjectID");
		pfnGetId = (PCmCallbackGetKeyObjectID)MmGetSystemRoutineAddress(&rn);

		RtlInitUnicodeString(&rn, L"CmCallbackReleaseKeyObjectIDEx");
		pfnRelease = (PCmCallbackReleaseKeyObjectIDEx)MmGetSystemRoutineAddress(&rn);

		if (pfnGetIdEx != NULL)
			LogMessage("[RegObj] Using CmCallbackGetKeyObjectIDEx\n");
		else if (pfnGetId != NULL)
			LogMessage("[RegObj] Using CmCallbackGetKeyObjectID\n");
		else
			LogMessage("[RegObj] No CmCallbackGetKeyObjectID available! Registry value protection disabled.\n");
	}

	PCUNICODE_STRING KeyName = NULL;
	NTSTATUS         status  = STATUS_NOT_FOUND;

	if (pfnGetIdEx != NULL)
	{
		status = pfnGetIdEx(&G_CmCallbackCookie, KeyObject, NULL, &KeyName, 0);
		if (!NT_SUCCESS(status) || KeyName == NULL)
			LogMessage("[RegObj] CmCallbackGetKeyObjectIDEx failed: 0x%08X\n", status);
	}
	else if (pfnGetId != NULL)
	{
		status = pfnGetId(KeyObject, NULL, (PUNICODE_STRING*)&KeyName);
		if (!NT_SUCCESS(status) || KeyName == NULL)
			LogMessage("[RegObj] CmCallbackGetKeyObjectID failed: 0x%08X\n", status);
	}

	if (!NT_SUCCESS(status) || KeyName == NULL)
		return FALSE;

	BOOLEAN result = IsRegistryPathProtected(KeyName);

	if (pfnRelease != NULL && KeyName != NULL)
		pfnRelease(KeyName);

	return result;
}

BOOLEAN
IsRegistryPathProtected(
	_In_ PCUNICODE_STRING KeyPath
)
{
	if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0)
		return FALSE;

	BOOLEAN Result = FALSE;
	KIRQL   LockIrql;

	KeAcquireSpinLock(&G_RegistryListLock, &LockIrql);

	PLIST_ENTRY Current = G_RegistryListHead.Flink;
	while (Current != &G_RegistryListHead)
	{
		PPROTECTED_REGISTRY_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_REGISTRY_ENTRY, ListEntry);
		Current = Current->Flink;

		UNICODE_STRING StoredPath;
		RtlInitUnicodeString(&StoredPath, Entry->KeyPath);

		static UNICODE_STRING RegMachine = { 0 };
		if (RegMachine.Buffer == NULL)
			RtlInitUnicodeString(&RegMachine, L"\\REGISTRY\\MACHINE\\");

		BOOLEAN matchAbs = RtlPrefixUnicodeString(&StoredPath, KeyPath, TRUE);
		BOOLEAN matchRel = FALSE;

		if (!matchAbs && RtlPrefixUnicodeString(&RegMachine, &StoredPath, TRUE))
		{
			UNICODE_STRING RelStored;
			RelStored.Length = (USHORT)(StoredPath.Length - RegMachine.Length);
			RelStored.MaximumLength = RelStored.Length;
			RelStored.Buffer = StoredPath.Buffer + (RegMachine.Length / sizeof(WCHAR));
			matchRel = RtlPrefixUnicodeString(&RelStored, KeyPath, TRUE);
		}

		if (matchAbs || matchRel)
		{
			Result = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_RegistryListLock, LockIrql);
	return Result;
}

static NTSTATUS
AddRegistryPathToProtectionList(
	_In_ PCWSTR KeyPath
)
{
	KIRQL LockIrql;

	if (G_RegistryCount >= MAX_PROTECTED_REGISTRY)
		return STATUS_INSUFFICIENT_RESOURCES;

	SIZE_T PathLen = wcsnlen_s(KeyPath, 256);
	if (PathLen == 0 || PathLen >= 256)
		return STATUS_BUFFER_OVERFLOW;

	KeAcquireSpinLock(&G_RegistryListLock, &LockIrql);

	PLIST_ENTRY Current = G_RegistryListHead.Flink;
	while (Current != &G_RegistryListHead)
	{
		PPROTECTED_REGISTRY_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_REGISTRY_ENTRY, ListEntry);
		Current = Current->Flink;
		if (_wcsicmp(Entry->KeyPath, KeyPath) == 0)
		{
			KeReleaseSpinLock(&G_RegistryListLock, LockIrql);
			return STATUS_DUPLICATE_NAME;
		}
	}

	PPROTECTED_REGISTRY_ENTRY NewEntry = static_cast<PPROTECTED_REGISTRY_ENTRY>(
		AllocPoolZero(sizeof(PROTECTED_REGISTRY_ENTRY)));
	if (NewEntry == NULL)
	{
		KeReleaseSpinLock(&G_RegistryListLock, LockIrql);
		return STATUS_NO_MEMORY;
	}

	wcscpy_s(NewEntry->KeyPath, 256, KeyPath);
	InsertHeadList(&G_RegistryListHead, &NewEntry->ListEntry);
	G_RegistryCount++;

	KeReleaseSpinLock(&G_RegistryListLock, LockIrql);
	LogMessage("Registry path '%ws' added to protection list.\n", KeyPath);
	return STATUS_SUCCESS;
}

static NTSTATUS
RemoveRegistryPathFromProtectionList(
	_In_ PCWSTR KeyPath
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_RegistryListLock, &LockIrql);

	BOOLEAN     Found = FALSE;
	PLIST_ENTRY Current = G_RegistryListHead.Flink;
	while (Current != &G_RegistryListHead)
	{
		PPROTECTED_REGISTRY_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_REGISTRY_ENTRY, ListEntry);
		Current = Current->Flink;
		if (_wcsicmp(Entry->KeyPath, KeyPath) == 0)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			G_RegistryCount--;
			Found = TRUE;
			break;
		}
	}

	KeReleaseSpinLock(&G_RegistryListLock, LockIrql);

	if (Found)
	{
		LogMessage("Registry path '%ws' removed from protection list.\n", KeyPath);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}