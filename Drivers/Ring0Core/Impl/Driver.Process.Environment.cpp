
PVOID
GetUserProcessEnvironment(
	_Out_ PSIZE_T EnvironmentSize
)
{
	*EnvironmentSize = 0;

	ULONG      EnvPid = FindProcessPidByName(L"explorer.exe");
	if (EnvPid == 0)
		EnvPid = FindProcessPidByName(L"winlogon.exe");
	if (EnvPid == 0)
		return NULL;

	PEPROCESS EnvProcess = NULL;
	NTSTATUS  Status = PsLookupProcessByProcessId(
		ULongToHandle(EnvPid), &EnvProcess);
	if (!NT_SUCCESS(Status))
		return NULL;

	KAPC_STATE ApcState;
	KeStackAttachProcess(EnvProcess, &ApcState);

	PROCESS_BASIC_INFORMATION Pbi;
	Status = ZwQueryInformationProcess(ZwCurrentProcess(),
		ProcessBasicInformation, &Pbi, sizeof(Pbi), NULL);

	if (!NT_SUCCESS(Status) || Pbi.PebBaseAddress == NULL)
	{
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(EnvProcess);
		return NULL;
	}

	PVOID  pParamsPtr   = NULL;
	PVOID  pEnvPtr      = NULL;

	__try
	{
		PVOID PEB_ProcessParams =
			reinterpret_cast<PVOID>(
			reinterpret_cast<ULONG_PTR>(Pbi.PebBaseAddress) + 0x20);

		if (SafeCopyMemory(&pParamsPtr, PEB_ProcessParams, sizeof(PVOID)) == STATUS_SUCCESS &&
			pParamsPtr != NULL)
		{
			PVOID ParamsEnv =
				reinterpret_cast<PVOID>(
				reinterpret_cast<ULONG_PTR>(pParamsPtr) + 0x80);

			SafeCopyMemory(&pEnvPtr, ParamsEnv, sizeof(PVOID));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		pEnvPtr = NULL;
	}

	if (pEnvPtr == NULL)
	{
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(EnvProcess);
		return NULL;
	}

	SIZE_T EnvLen = 0;
	BOOLEAN PrevNull = FALSE;

	for (SIZE_T Offset = 0; Offset < (1 << 20); Offset += sizeof(WCHAR))  
	{
		WCHAR Ch = 0;
		PVOID Addr = reinterpret_cast<PVOID>(
			reinterpret_cast<ULONG_PTR>(pEnvPtr) + Offset);

		if (SafeCopyMemory(&Ch, Addr, sizeof(WCHAR)) != STATUS_SUCCESS)
			break;

		if (Ch == 0)
		{
			if (PrevNull)
			{
				EnvLen = Offset + sizeof(WCHAR);
				break;
			}
			PrevNull = TRUE;
		}
		else
		{
			PrevNull = FALSE;
		}
	}

	if (EnvLen == 0 || EnvLen > (1 << 20))
	{
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(EnvProcess);
		return NULL;
	}

	PVOID EnvBlock = ExAllocatePool2(POOL_FLAG_PAGED, EnvLen, POOL_TAG);
	if (EnvBlock != NULL)
	{
		NTSTATUS CopyStatus = SafeCopyMemory(EnvBlock, pEnvPtr, EnvLen);
		if (!NT_SUCCESS(CopyStatus))
		{
			ExFreePoolWithTag(EnvBlock, POOL_TAG);
			EnvBlock = NULL;
		}
		else
		{
			*EnvironmentSize = EnvLen;
		}
	}

	KeUnstackDetachProcess(&ApcState);
	ObfDereferenceObject(EnvProcess);
	return EnvBlock;
}
