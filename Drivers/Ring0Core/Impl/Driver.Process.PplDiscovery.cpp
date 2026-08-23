
NTSTATUS
FindPplOffset(
	_Out_ PULONG PsProtectionOffset
)
{
	PAGED_CODE();

	*PsProtectionOffset = 0;

	CONST PULONG CandidateOffsets = static_cast<PULONG>(
		AllocPoolZero(PAGE_SIZE * sizeof(ULONG)));
	if (CandidateOffsets == NULL)
		return STATUS_NO_MEMORY;

	ULONG NumProtectedProcesses = 0, BestMatchCount = 0, Offset = 0;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = NULL, Entry;
	NTSTATUS Status;

	if ((Status = ZwQuerySystemInformation(
		SystemProcessInformation, SystemProcessInfo, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		goto finished;

	SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
		AllocPoolZero(static_cast<SIZE_T>(2) * Size));
	if (SystemProcessInfo == NULL)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	Status = ZwQuerySystemInformation(
		SystemProcessInformation, SystemProcessInfo, 2 * Size, NULL);
	if (!NT_SUCCESS(Status))
		goto finished;

	Entry = SystemProcessInfo;
	while (TRUE)
	{
		OBJECT_ATTRIBUTES Oa = RTL_CONSTANT_OBJECT_ATTRIBUTES(
			static_cast<PUNICODE_STRING>(NULL), OBJ_KERNEL_HANDLE);
		CLIENT_ID Cid = { Entry->UniqueProcessId, NULL };
		HANDLE TempHandle;
		Status = ZwOpenProcess(
			&TempHandle, PROCESS_QUERY_LIMITED_INFORMATION, &Oa, &Cid);
		if (NT_SUCCESS(Status))
		{
			PS_PROTECTION ProtectionInfo;
			Status = ZwQueryInformationProcess(
				TempHandle, ProcessProtectionInformation,
				&ProtectionInfo, sizeof(ProtectionInfo), NULL);

			if (NT_SUCCESS(Status) && ProtectionInfo.Level > 0)
			{
				PEPROCESS EProcess;
				Status = ObReferenceObjectByHandle(
					TempHandle, PROCESS_QUERY_LIMITED_INFORMATION,
					*PsProcessType, KernelMode,
					reinterpret_cast<PVOID*>(&EProcess), NULL);
				if (NT_SUCCESS(Status))
				{
					CONST ULONG_PTR End = ALIGN_UP_BY(EProcess, PAGE_SIZE) -
						reinterpret_cast<ULONG_PTR>(EProcess);
					for (ULONG_PTR i = EPROCESS_SCAN_START; i < End; ++i)
					{
						CONST PPS_PROTECTION Candidate = reinterpret_cast<PPS_PROTECTION>(
							reinterpret_cast<PUCHAR>(EProcess) + i);
						if (Candidate->Level == ProtectionInfo.Level)
							CandidateOffsets[i]++;
					}
					NumProtectedProcesses++;
					ObfDereferenceObject(EProcess);
				}
			}
			ZwClose(TempHandle);
		}

		if (Entry->NextEntryOffset == 0)
			break;
		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
			reinterpret_cast<ULONG_PTR>(Entry) + Entry->NextEntryOffset);
	}

	for (ULONG i = EPROCESS_SCAN_START; i < PAGE_SIZE; ++i)
	{
		if (CandidateOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumProtectedProcesses)
			{
				LogMessage("Ambiguous PS_PROTECTION offset.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			Offset = i;
			BestMatchCount = CandidateOffsets[i];
		}
	}

	if (BestMatchCount == 0 && NumProtectedProcesses > 0)
	{
		LogMessage("PS_PROTECTION offset not found.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumProtectedProcesses)
	{
		LogMessage("PS_PROTECTION offset +0x%02X only matches %u/%u.\n",
			Offset, BestMatchCount, NumProtectedProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (NumProtectedProcesses > 1)
		LogMessage("Found PS_PROTECTION offset +0x%02X.\n", Offset);

	*PsProtectionOffset = Offset;

finished:
	if (SystemProcessInfo != NULL)
		ExFreePoolWithTag(SystemProcessInfo, POOL_TAG);
	ExFreePoolWithTag(CandidateOffsets, POOL_TAG);
	return Status;
}
