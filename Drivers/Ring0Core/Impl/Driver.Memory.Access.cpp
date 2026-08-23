
static NTSTATUS
SafeCopyMemory(
	_Out_writes_bytes_all_(Size) PVOID Dest,
	_In_ PVOID Src,
	_In_ SIZE_T Size
)
{
	if (Size == 0)
		return STATUS_SUCCESS;

	if (G_pMmCopyMemory != NULL)
	{
		MM_COPY_ADDRESS SrcAddr;
		SrcAddr.VirtualAddress = Src;
		SIZE_T Transferred = 0;
		return G_pMmCopyMemory(Dest, SrcAddr, Size,
			MM_COPY_MEMORY_VIRTUAL, &Transferred);
	}

	SIZE_T Remaining = Size;
	SIZE_T Offset = 0;

	while (Remaining > 0)
	{
		PUCHAR CurrDest = reinterpret_cast<PUCHAR>(Dest) + Offset;
		PUCHAR CurrSrc = reinterpret_cast<PUCHAR>(Src) + Offset;

		if (!MmIsAddressValid(CurrDest) || !MmIsAddressValid(CurrSrc))
			return STATUS_INVALID_ADDRESS;

		SIZE_T DestPageEnd = PAGE_SIZE -
			(reinterpret_cast<ULONG_PTR>(CurrDest) & (PAGE_SIZE - 1));
		SIZE_T SrcPageEnd = PAGE_SIZE -
			(reinterpret_cast<ULONG_PTR>(CurrSrc) & (PAGE_SIZE - 1));
		SIZE_T Chunk = (Remaining < DestPageEnd) ? Remaining : DestPageEnd;
		if (Chunk > SrcPageEnd)
			Chunk = SrcPageEnd;

		__try
		{
			RtlCopyMemory(CurrDest, CurrSrc, Chunk);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

		Offset += Chunk;
		Remaining -= Chunk;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
ReadMemory(
	_In_ ULONG ProcessId,
	_In_ ULONG_PTR Address,
	_In_ ULONG Size,
	_Out_writes_bytes_(Size) PVOID OutputBuffer
)
{
	if (Size == 0 || OutputBuffer == NULL)
		return STATUS_INVALID_PARAMETER;

	if (ProcessId == 0)
	{
		return SafeCopyMemory(OutputBuffer,
			reinterpret_cast<PVOID>(Address), Size);
	}
	else
	{
		PEPROCESS Process = NULL;
		NTSTATUS Status = PsLookupProcessByProcessId(
			ULongToHandle(ProcessId), &Process);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("ReadMemory: PID %u not found (0x%08X).\n",
				ProcessId, Status);
			return Status;
		}

		KAPC_STATE ApcState;
		KeStackAttachProcess(Process, &ApcState);

		Status = SafeCopyMemory(OutputBuffer,
			reinterpret_cast<PVOID>(Address), Size);

		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		return Status;
	}
}

NTSTATUS
WriteMemory(
	_In_ ULONG ProcessId,
	_In_ ULONG_PTR Address,
	_In_ ULONG Size,
	_In_reads_bytes_(Size) PVOID Data
)
{
	if (Size == 0 || Data == NULL)
		return STATUS_INVALID_PARAMETER;

	if (ProcessId == 0)
	{
		return SafeCopyMemory(reinterpret_cast<PVOID>(Address),
			Data, Size);
	}
	else
	{
		PEPROCESS Process = NULL;
		NTSTATUS Status = PsLookupProcessByProcessId(
			ULongToHandle(ProcessId), &Process);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("WriteMemory: PID %u not found (0x%08X).\n",
				ProcessId, Status);
			return Status;
		}

		KAPC_STATE ApcState;
		KeStackAttachProcess(Process, &ApcState);

		Status = SafeCopyMemory(reinterpret_cast<PVOID>(Address),
			Data, Size);

		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Process);
		return Status;
	}
}
