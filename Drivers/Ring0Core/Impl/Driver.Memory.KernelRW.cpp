
static ULONG_PTR G_KrnlCiOptionsAddr = 0;
static ULONG     G_KrnlCiOptionsOrig = 0;
static BOOLEAN   G_KrnlDseDisabled = FALSE;

static NTSTATUS
KrnlReadMemory(
	IN  PVOID   Address,
	OUT PVOID   Buffer,
	IN  SIZE_T  Size
)
{
	if (Address == NULL || Buffer == NULL || Size == 0)
		return STATUS_INVALID_PARAMETER;

	if (!MmIsAddressValid(Address))
		return STATUS_INVALID_ADDRESS;

	if (!MmIsAddressValid(reinterpret_cast<PUCHAR>(Address) + Size - 1))
		return STATUS_INVALID_ADDRESS;

	__try
	{
		RtlCopyMemory(Buffer, Address, Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LogMessage("KrnlReadMemory: exception at %p (code 0x%08X).\n",
			Address, GetExceptionCode());
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS
KrnlWriteMemoryMdl(
	IN PVOID  Address,
	IN PVOID  Buffer,
	IN SIZE_T Size
)
{
	PMDL     Mdl;
	PVOID    MappedAddr;

	Mdl = IoAllocateMdl(Address, static_cast<ULONG>(Size), FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		LogMessage("KrnlWriteMemoryMdl: IoAllocateMdl failed for %p.\n", Address);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LogMessage("KrnlWriteMemoryMdl: MmProbeAndLockPages failed (code 0x%08X).\n",
			GetExceptionCode());
		IoFreeMdl(Mdl);
		return STATUS_ACCESS_VIOLATION;
	}

	MappedAddr = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (MappedAddr == NULL)
	{
		LogMessage("KrnlWriteMemoryMdl: MmMapLockedPagesSpecifyCache failed.\n");
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(MappedAddr, Buffer, Size);

	MmUnmapLockedPages(MappedAddr, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}

static NTSTATUS
KrnlWriteMemory(
	IN PVOID              Address,
	IN PVOID              Buffer,
	IN SIZE_T             Size,
	IN KRNL_MEMRW_METHOD  Method
)
{
	NTSTATUS Status;

	if (Address == NULL || Buffer == NULL || Size == 0)
		return STATUS_INVALID_PARAMETER;

	if (!MmIsAddressValid(Address) ||
		!MmIsAddressValid(reinterpret_cast<PUCHAR>(Address) + Size - 1))
	{
		LogMessage("KrnlWriteMemory: address %p not valid.\n", Address);
		return STATUS_INVALID_ADDRESS;
	}

	switch (Method)
	{
	case KrnlMemRwMdl:
		Status = KrnlWriteMemoryMdl(Address, Buffer, Size);
		break;

	case KrnlMemRwDirect:
		__try
		{
			RtlCopyMemory(Address, Buffer, Size);
			Status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogMessage("KrnlWriteMemory(Direct): write exception at %p (code 0x%08X).\n",
				Address, GetExceptionCode());
			Status = STATUS_ACCESS_VIOLATION;
		}
		break;

	case KrnlMemRwAuto:
	default:
		Status = KrnlWriteMemoryMdl(Address, Buffer, Size);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("KrnlWriteMemory: MDL failed, falling back to direct write.\n");
			__try
			{
				RtlCopyMemory(Address, Buffer, Size);
				Status = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				LogMessage("KrnlWriteMemory(Direct): write exception at %p (code 0x%08X).\n",
					Address, GetExceptionCode());
				Status = STATUS_ACCESS_VIOLATION;
			}
		}
		break;
	}

	return Status;
}

static NTSTATUS
KrnlFindModuleByName(
	IN  PCWSTR    ModuleName,
	OUT PVOID*    BaseAddress,
	OUT PULONG    ImageSize
)
{
	SIZE_T          NameLen;
	PMY_MODULE_INFO ModInfo;

	if (ModuleName == NULL || BaseAddress == NULL || ImageSize == NULL)
		return STATUS_INVALID_PARAMETER;

	*BaseAddress = NULL;
	*ImageSize = 0;

	RtlStringCbLengthW(ModuleName, NTSTRSAFE_MAX_CCH * sizeof(WCHAR), &NameLen);
	if (NameLen == 0)
		return STATUS_INVALID_PARAMETER;

	ModInfo = GetSystemModuleInfo();
	if (ModInfo == NULL)
	{
		LogMessage("KrnlFindModuleByName: GetSystemModuleInfo failed.\n");
		return STATUS_UNSUCCESSFUL;
	}

	for (ULONG i = 0; i < ModInfo->ModulesCount; i++)
	{
		PMY_MODULE_ENTRY Entry = &ModInfo->Modules[i];

		PCSTR FilePart = reinterpret_cast<PCSTR>(
			reinterpret_cast<PUCHAR>(Entry->FullPathName) + Entry->OffsetToFileName);

		BOOLEAN Match = TRUE;
		for (ULONG j = 0; j < NameLen / sizeof(WCHAR); j++)
		{
			CHAR c = FilePart[j];
			if (c == '\0' || static_cast<WCHAR>(c) != ModuleName[j])
			{
				Match = FALSE;
				break;
			}
		}

		if (Match && FilePart[NameLen / sizeof(WCHAR)] == '\0')
		{
			*BaseAddress = Entry->ImageBase;
			*ImageSize   = Entry->ImageSize;
			ExFreePoolWithTag(ModInfo, POOL_TAG);
			return STATUS_SUCCESS;
		}
	}

	ExFreePoolWithTag(ModInfo, POOL_TAG);
	return STATUS_NOT_FOUND;
}

static PVOID
KrnlScanPattern(
	IN PVOID  Base,
	IN ULONG  Size,
	IN PUCHAR Pattern,
	IN ULONG  PatternSize
)
{
	if (Base == NULL || Pattern == NULL || Size == 0 || PatternSize == 0)
		return NULL;

	PUCHAR Start = reinterpret_cast<PUCHAR>(Base);
	PUCHAR End   = Start + Size - PatternSize;

	for (PUCHAR Curr = Start; Curr < End; Curr++)
	{
		ULONG j;
		for (j = 0; j < PatternSize; j++)
		{
			if (Pattern[j] != 0xCC && Curr[j] != Pattern[j])
				break;
		}

		if (j == PatternSize)
			return Curr;
	}

	return NULL;
}

static NTSTATUS
KrnlLocateCiOptions(
	OUT PULONG_PTR Address
)
{
	PVOID     CiBase;
	ULONG     CiSize;
	NTSTATUS  Status;
	PVOID     MatchPtr;
	UCHAR     Signature[] = { 0xC7, 0x05 };
	ULONG     Immediate;
	LONG      RelOffset;
	PVOID     Candidate;
	ULONG     VerifyValue;

	if (Address == NULL)
		return STATUS_INVALID_PARAMETER;

	*Address = 0;

	Status = KrnlFindModuleByName(L"CI.dll", &CiBase, &CiSize);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("KrnlLocateCiOptions: CI.dll not found (status 0x%08X).\n", Status);
		return Status;
	}

	LogMessage("KrnlLocateCiOptions: CI.dll at %p, size 0x%X.\n", CiBase, CiSize);

	MatchPtr = CiBase;
	ULONG SearchSize = CiSize;

	while ((MatchPtr = KrnlScanPattern(MatchPtr, SearchSize,
		reinterpret_cast<PUCHAR>(Signature), sizeof(Signature))) != NULL)
	{
		ULONG_PTR CurrOff = reinterpret_cast<ULONG_PTR>(MatchPtr) -
			reinterpret_cast<ULONG_PTR>(CiBase);
		SearchSize = CiSize - static_cast<ULONG>(CurrOff) - sizeof(Signature);
		MatchPtr = reinterpret_cast<PUCHAR>(MatchPtr) + sizeof(Signature);

		RelOffset = *reinterpret_cast<PLONG>(
			reinterpret_cast<PUCHAR>(MatchPtr));
		Immediate = *reinterpret_cast<PULONG>(
			reinterpret_cast<PUCHAR>(MatchPtr) + 4);

		Candidate = reinterpret_cast<PVOID>(
			reinterpret_cast<PUCHAR>(MatchPtr) + 4 + RelOffset);

		if (Immediate != 0 && Immediate != 6 && Immediate != 1)
			continue;

		if (Candidate < CiBase ||
			Candidate >= reinterpret_cast<PUCHAR>(CiBase) + CiSize)
			continue;

		Status = KrnlReadMemory(Candidate, &VerifyValue, sizeof(VerifyValue));
		if (!NT_SUCCESS(Status))
			continue;

		if (VerifyValue == Immediate)
		{
			*Address = reinterpret_cast<ULONG_PTR>(Candidate);
			LogMessage("KrnlLocateCiOptions: g_CiOptions = %p, value = 0x%X.\n",
				Candidate, VerifyValue);
			return STATUS_SUCCESS;
		}
	}

	MatchPtr = reinterpret_cast<PUCHAR>(CiBase);
	SearchSize = CiSize;

	while ((MatchPtr = KrnlScanPattern(MatchPtr, SearchSize,
		reinterpret_cast<PUCHAR>(Signature), sizeof(Signature))) != NULL)
	{
		ULONG_PTR CurrOff = reinterpret_cast<ULONG_PTR>(MatchPtr) -
			reinterpret_cast<ULONG_PTR>(CiBase);
		SearchSize = CiSize - static_cast<ULONG>(CurrOff) - sizeof(Signature);
		MatchPtr = reinterpret_cast<PUCHAR>(MatchPtr) + sizeof(Signature);

		RelOffset = *reinterpret_cast<PLONG>(
			reinterpret_cast<PUCHAR>(MatchPtr));
		Immediate = *reinterpret_cast<PULONG>(
			reinterpret_cast<PUCHAR>(MatchPtr) + 4);

		Candidate = reinterpret_cast<PVOID>(
			reinterpret_cast<PUCHAR>(MatchPtr) + 4 + RelOffset);

		if (Candidate < CiBase ||
			Candidate >= reinterpret_cast<PUCHAR>(CiBase) + CiSize)
			continue;

		*Address = reinterpret_cast<ULONG_PTR>(Candidate);
		LogMessage("KrnlLocateCiOptions: (relaxed) g_CiOptions = %p, immediate = 0x%X.\n",
			Candidate, Immediate);
		return STATUS_SUCCESS;
	}

	LogMessage("KrnlLocateCiOptions: could not find g_CiOptions in CI.dll.\n");
	return STATUS_NOT_FOUND;
}

static NTSTATUS
KrnlDisableDse(
	OUT PDSE_CONTROL_OUTPUT Output OPTIONAL
)
{
	ULONG_PTR CiOptAddr;
	ULONG     OrigValue;
	ULONG     DisableValue;
	NTSTATUS  Status;

	Status = KrnlLocateCiOptions(&CiOptAddr);
	if (!NT_SUCCESS(Status))
	{
		if (Output != NULL)
		{
			Output->CiOptionsAddress = 0;
			Output->OriginalValue    = 0;
			Output->CurrentValue     = 0;
			Output->Status           = Status;
		}
		return Status;
	}

	Status = KrnlReadMemory(
		reinterpret_cast<PVOID>(CiOptAddr),
		&OrigValue,
		sizeof(OrigValue));

	if (!NT_SUCCESS(Status))
	{
		LogMessage("KrnlDisableDse: failed to read g_CiOptions (status 0x%08X).\n", Status);
		if (Output != NULL)
		{
			Output->CiOptionsAddress = CiOptAddr;
			Output->OriginalValue    = 0;
			Output->CurrentValue     = 0;
			Output->Status           = Status;
		}
		return Status;
	}

	LogMessage("KrnlDisableDse: g_CiOptions at %p, current = 0x%X.\n", CiOptAddr, OrigValue);

	DisableValue = 0;

	Status = KrnlWriteMemory(
		reinterpret_cast<PVOID>(CiOptAddr),
		&DisableValue,
		sizeof(DisableValue),
		KrnlMemRwAuto);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("KrnlDisableDse: write failed (status 0x%08X).\n", Status);
		if (Output != NULL)
		{
			Output->CiOptionsAddress = CiOptAddr;
			Output->OriginalValue    = OrigValue;
			Output->CurrentValue     = OrigValue;
			Output->Status           = Status;
		}
		return Status;
	}

	ULONG VerifyValue = 0;
	Status = KrnlReadMemory(
		reinterpret_cast<PVOID>(CiOptAddr),
		&VerifyValue,
		sizeof(VerifyValue));

	G_KrnlCiOptionsAddr = CiOptAddr;
	G_KrnlCiOptionsOrig = OrigValue;
	G_KrnlDseDisabled   = NT_SUCCESS(Status) && (VerifyValue == DisableValue);

	LogMessage("KrnlDisableDse: verify %s (read back 0x%X).\n",
		G_KrnlDseDisabled ? "OK" : "FAILED", VerifyValue);

	if (Output != NULL)
	{
		Output->CiOptionsAddress = CiOptAddr;
		Output->OriginalValue    = OrigValue;
		Output->CurrentValue     = VerifyValue;
		Output->Status           = Status;
	}

	return G_KrnlDseDisabled ? STATUS_SUCCESS : STATUS_VERIFIER_STOP;
}

static NTSTATUS
KrnlRestoreDse(
	OUT PDSE_CONTROL_OUTPUT Output OPTIONAL
)
{
	ULONG    CurrentValue;
	NTSTATUS Status;

	if (!G_KrnlDseDisabled || G_KrnlCiOptionsAddr == 0)
	{
		LogMessage("KrnlRestoreDse: DSE was not disabled or address unknown.\n");
		if (Output != NULL)
		{
			Output->CiOptionsAddress = G_KrnlCiOptionsAddr;
			Output->OriginalValue    = G_KrnlCiOptionsOrig;
			Output->CurrentValue     = 0;
			Output->Status           = STATUS_INVALID_DEVICE_STATE;
		}
		return STATUS_INVALID_DEVICE_STATE;
	}

	Status = KrnlWriteMemory(
		reinterpret_cast<PVOID>(G_KrnlCiOptionsAddr),
		&G_KrnlCiOptionsOrig,
		sizeof(G_KrnlCiOptionsOrig),
		KrnlMemRwAuto);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("KrnlRestoreDse: write failed (status 0x%08X).\n", Status);
		if (Output != NULL)
		{
			Output->CiOptionsAddress = G_KrnlCiOptionsAddr;
			Output->OriginalValue    = G_KrnlCiOptionsOrig;
			Output->CurrentValue     = 0;
			Output->Status           = Status;
		}
		return Status;
	}

	Status = KrnlReadMemory(
		reinterpret_cast<PVOID>(G_KrnlCiOptionsAddr),
		&CurrentValue,
		sizeof(CurrentValue));

	G_KrnlDseDisabled   = FALSE;
	G_KrnlCiOptionsAddr = 0;
	G_KrnlCiOptionsOrig = 0;

	LogMessage("KrnlRestoreDse: g_CiOptions restored to 0x%X (status 0x%08X).\n",
		CurrentValue, Status);

	if (Output != NULL)
	{
		Output->CiOptionsAddress = 0;
		Output->OriginalValue    = 0;
		Output->CurrentValue     = CurrentValue;
		Output->Status           = Status;
	}

	return Status;
}

static NTSTATUS
KrnlQueryDse(
	OUT PDSE_CONTROL_OUTPUT Output
)
{
	ULONG_PTR CiOptAddr;
	ULONG     CurrentValue;
	NTSTATUS  Status;

	if (G_KrnlDseDisabled && G_KrnlCiOptionsAddr != 0)
	{
		CiOptAddr = G_KrnlCiOptionsAddr;
	}
	else
	{
		Status = KrnlLocateCiOptions(&CiOptAddr);
		if (!NT_SUCCESS(Status))
		{
			Output->CiOptionsAddress = 0;
			Output->OriginalValue    = 0;
			Output->CurrentValue     = 0;
			Output->Status           = Status;
			return Status;
		}
	}

	Status = KrnlReadMemory(
		reinterpret_cast<PVOID>(CiOptAddr),
		&CurrentValue,
		sizeof(CurrentValue));

	Output->CiOptionsAddress = CiOptAddr;
	Output->OriginalValue    = G_KrnlDseDisabled ? G_KrnlCiOptionsOrig : CurrentValue;
	Output->CurrentValue     = CurrentValue;
	Output->Status           = Status;

	LogMessage("KrnlQueryDse: g_CiOptions at %p = 0x%X (orig=0x%X).\n",
		CiOptAddr, CurrentValue, Output->OriginalValue);

	return Status;
}

static NTSTATUS
KrnlCheckWriteResult(
	IN PVOID  Address,
	IN PVOID  ExpectedBuffer,
	IN SIZE_T Size
)
{
	PUCHAR   ReadBack;
	NTSTATUS Status;
	BOOLEAN  Match;

	ReadBack = reinterpret_cast<PUCHAR>(
		ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, POOL_TAG));
	if (ReadBack == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	Status = KrnlReadMemory(Address, ReadBack, Size);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(ReadBack, POOL_TAG);
		return Status;
	}

	Match = (RtlCompareMemory(ReadBack, ExpectedBuffer, Size) == Size);

	ExFreePoolWithTag(ReadBack, POOL_TAG);

	return Match ? STATUS_SUCCESS : STATUS_VERIFIER_STOP;
}
