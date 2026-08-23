
NTSTATUS
SetProcessPpl(
	_In_ ULONG ProcessId,
	_In_ UCHAR ProtectionType,
	_In_ UCHAR ProtectionSigner,
	_In_ BOOLEAN Audit
)
{
	PAGED_CODE();

	if (G_PplOffset == 0)
		return STATUS_NOT_FOUND;

	if (ProtectionType >= static_cast<UCHAR>(PsProtectedTypeMax) ||
		ProtectionSigner >= static_cast<UCHAR>(PsProtectedSignerMax))
		return STATUS_INVALID_PARAMETER;

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("SetProcessPpl: PID %u not found (0x%08X).\n", ProcessId, Status);
		return Status;
	}

	PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
		reinterpret_cast<PUCHAR>(Process) + G_PplOffset);

	PsProtection->s.Type = static_cast<PS_PROTECTED_TYPE>(ProtectionType);
	PsProtection->s.Signer = static_cast<PS_PROTECTED_SIGNER>(ProtectionSigner);
	PsProtection->s.Audit = Audit;

	LogMessage("PID %u PPL set: Type=%u Signer=%u Audit=%u (Raw=0x%02X).\n",
		ProcessId, ProtectionType, ProtectionSigner, Audit, PsProtection->Level);

	ObfDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS
RemoveProcessPpl(
	_In_ ULONG ProcessId
)
{
	PAGED_CODE();

	if (G_PplOffset == 0)
		return STATUS_NOT_FOUND;

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("RemoveProcessPpl: PID %u not found (0x%08X).\n", ProcessId, Status);
		return Status;
	}

	PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
		reinterpret_cast<PUCHAR>(Process) + G_PplOffset);

	PsProtection->Level = 0;

	LogMessage("PID %u PPL removed.\n", ProcessId);

	ObfDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS
QueryProcessPpl(
	_In_  ULONG              ProcessId,
	_Out_ PPPL_QUERY_OUTPUT  Output
)
{
	PAGED_CODE();

	if (Output == NULL)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Output, sizeof(PPL_QUERY_OUTPUT));
	Output->ProcessId = ProcessId;

	if (G_PplOffset == 0)
		return STATUS_NOT_FOUND;

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("QueryProcessPpl: PID %u not found (0x%08X).\n", ProcessId, Status);
		return Status;
	}

	PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(
		reinterpret_cast<PUCHAR>(Process) + G_PplOffset);

	Output->ProtectionType   = (UCHAR)PsProtection->s.Type;
	Output->ProtectionSigner = (UCHAR)PsProtection->s.Signer;
	Output->Audit            = PsProtection->s.Audit;
	Output->IsProtected      = (PsProtection->Level > 0);
	Output->RawLevel         = PsProtection->Level;

	LogMessage("PID %u PPL: Type=%u Signer=%u Audit=%u Level=0x%02X.\n",
		ProcessId,
		Output->ProtectionType,
		Output->ProtectionSigner,
		Output->Audit,
		Output->RawLevel);

	ObfDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS
SetProcessCritical(
	_In_ ULONG ProcessId
)
{
	PAGED_CODE();

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("SetProcessCritical: PID %u not found (0x%08X).\n", ProcessId, Status);
		return Status;
	}

	HANDLE hProcess = NULL;
	Status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_SET_INFORMATION,
		*PsProcessType,
		KernelMode,
		&hProcess);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("SetProcessCritical: ObOpenObjectByPointer failed 0x%08X.\n", Status);
		ObfDereferenceObject(Process);
		return Status;
	}

	ULONG BreakOnTermination = 1;
	Status = ZwSetInformationProcess(
		hProcess,
		ProcessBreakOnTermination,
		&BreakOnTermination,
		sizeof(ULONG));

	if (NT_SUCCESS(Status))
		LogMessage("PID %u set as critical process.\n", ProcessId);
	else
		LogMessage("SetProcessCritical: ZwSetInformationProcess failed 0x%08X.\n", Status);

	ZwClose(hProcess);
	ObfDereferenceObject(Process);
	return Status;
}

NTSTATUS
RemoveProcessCritical(
	_In_ ULONG ProcessId
)
{
	PAGED_CODE();

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("RemoveProcessCritical: PID %u not found (0x%08X).\n", ProcessId, Status);
		return Status;
	}

	HANDLE hProcess = NULL;
	Status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_SET_INFORMATION,
		*PsProcessType,
		KernelMode,
		&hProcess);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("RemoveProcessCritical: ObOpenObjectByPointer failed 0x%08X.\n", Status);
		ObfDereferenceObject(Process);
		return Status;
	}

	ULONG BreakOnTermination = 0;
	Status = ZwSetInformationProcess(
		hProcess,
		ProcessBreakOnTermination,
		&BreakOnTermination,
		sizeof(ULONG));

	if (NT_SUCCESS(Status))
		LogMessage("PID %u removed from critical process.\n", ProcessId);
	else
		LogMessage("RemoveProcessCritical: ZwSetInformationProcess failed 0x%08X.\n", Status);

	ZwClose(hProcess);
	ObfDereferenceObject(Process);
	return Status;
}
