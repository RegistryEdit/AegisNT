
static ULONG
FindProcessPidByName(
	_In_ PCWSTR ImageName
)
{
	ULONG BufSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		SystemProcessInformation, NULL, 0, &BufSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		return 0;

	PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
	if (SysBuf == NULL)
		return 0;

	Status = ZwQuerySystemInformation(
		SystemProcessInformation, SysBuf, BufSize * 2, NULL);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		return 0;
	}

	ULONG TargetPid = 0;
	PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
	while (TRUE)
	{
		if (Entry->ImageName.Length > 0 && Entry->ImageName.Buffer != NULL)
		{
			UNICODE_STRING UniTarget;
			RtlInitUnicodeString(&UniTarget, ImageName);
			if (RtlCompareUnicodeString(&Entry->ImageName, &UniTarget, TRUE) == 0)
			{
				TargetPid = (ULONG)(ULONG_PTR)Entry->UniqueProcessId;
				break;
			}
		}
		if (Entry->NextEntryOffset == 0)
			break;
		Entry = (PSYSTEM_PROCESS_INFORMATION)
			((PUCHAR)Entry + Entry->NextEntryOffset);
	}

	ExFreePoolWithTag(SysBuf, POOL_TAG);
	return TargetPid;
}
