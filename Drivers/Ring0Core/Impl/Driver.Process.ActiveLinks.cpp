
static NTSTATUS
FindActiveProcessLinksOffset(
	_Out_ PULONG Offset
)
{
	*Offset = 0;

	PEPROCESS SystemProc;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(4), &SystemProc);
	if (!NT_SUCCESS(Status))
		return Status;

	ULONG TestOffset = 0x448;
	PLIST_ENTRY Entry = (PLIST_ENTRY)((PUCHAR)SystemProc + TestOffset);

	__try
	{
		if ((ULONG_PTR)Entry->Flink > 0xFFFF000000000000ULL &&
			(ULONG_PTR)Entry->Blink > 0xFFFF000000000000ULL)
		{
			*Offset = TestOffset;
			ObfDereferenceObject(SystemProc);
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	for (ULONG off = 0x200; off <= 0x800; off += sizeof(ULONG_PTR))
	{
		PLIST_ENTRY Candidate = (PLIST_ENTRY)((PUCHAR)SystemProc + off);

		__try
		{
			if ((ULONG_PTR)Candidate->Flink < 0xFFFF000000000000ULL ||
				(ULONG_PTR)Candidate->Blink < 0xFFFF000000000000ULL)
				continue;

			if (Candidate->Flink->Blink != Candidate)
				continue;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}

		*Offset = off;
		ObfDereferenceObject(SystemProc);
		return STATUS_SUCCESS;
	}

	ObfDereferenceObject(SystemProc);
	return STATUS_NOT_FOUND;
}
