
static PMY_MODULE_INFO
GetSystemModuleInfo(VOID)
{
	ULONG Size = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)11, NULL, 0, &Size);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		LogMessage("GetSystemModuleInfo: size query failed 0x%08X\n", Status);
		return NULL;
	}

	PMY_MODULE_INFO Info = (PMY_MODULE_INFO)
		ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, POOL_TAG);
	if (Info == NULL)
		return NULL;

	Status = ZwQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)11, Info, Size, &Size);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("GetSystemModuleInfo: query failed 0x%08X\n", Status);
		ExFreePoolWithTag(Info, POOL_TAG);
		return NULL;
	}

	return Info;
}

static BOOLEAN
IsAddressInSystemModule(
	_In_ PVOID Address,
	_In_ PMY_MODULE_INFO ModuleInfo
)
{
	if (ModuleInfo == NULL || Address == NULL)
		return FALSE;

	ULONG_PTR AddrVal = (ULONG_PTR)Address;

	for (ULONG i = 0; i < ModuleInfo->ModulesCount; i++)
	{
		PMY_MODULE_ENTRY Module = &ModuleInfo->Modules[i];
		ULONG_PTR Base = (ULONG_PTR)Module->ImageBase;
		ULONG_PTR End  = Base + Module->ImageSize;

		if (AddrVal >= Base && AddrVal < End)
		{
			PCSTR FullPath = (PCSTR)Module->FullPathName;
			PCSTR FileName = FullPath + Module->OffsetToFileName;

			LogMessage("Address 0x%p belongs to module: %s\n", Address, FileName);

			for (ULONG j = 0; j < 22; j++)
			{
				CHAR c = FullPath[j];
				if (c >= 'a' && c <= 'z')
					c = (CHAR)(c - 'a' + 'A');
				if (FullPath[j] == '\0' || c != "\\SYSTEMROOT\\SYSTEM32\\"[j])
					break;
				if (j == 21)
					return TRUE;
			}
			return FALSE;
		}
	}

	return FALSE;
}

static NTSTATUS
GetModuleNameForAddress(
	_In_     PVOID            Address,
	_In_     PMY_MODULE_INFO  ModuleInfo,
	_Out_writes_(NameLength)  PWSTR ModuleName,
	_In_     ULONG            NameLength
)
{
	if (ModuleInfo == NULL || Address == NULL || NameLength == 0)
		return STATUS_INVALID_PARAMETER;

	ULONG_PTR AddrVal = (ULONG_PTR)Address;

	for (ULONG i = 0; i < ModuleInfo->ModulesCount; i++)
	{
		PMY_MODULE_ENTRY Module = &ModuleInfo->Modules[i];
		ULONG_PTR Base = (ULONG_PTR)Module->ImageBase;
		ULONG_PTR End = Base + Module->ImageSize;

		if (AddrVal >= Base && AddrVal < End)
		{
			PCSTR FullPath = (PCSTR)Module->FullPathName;
			PCSTR FileName = FullPath + Module->OffsetToFileName;

			ULONG j = 0;
			while (j < NameLength - 1 && FileName[j] != '\0')
			{
				ModuleName[j] = (WCHAR)FileName[j];
				j++;
			}
			ModuleName[j] = L'\0';
			return STATUS_SUCCESS;
		}
	}

	ModuleName[0] = L'\0';
	return STATUS_NOT_FOUND;
}
