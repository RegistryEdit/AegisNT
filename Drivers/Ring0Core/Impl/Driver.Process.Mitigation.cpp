
#define ProcessMitigationPolicy  52

static NTSTATUS
QueryMitigation(
	_In_ ULONG ProcessId,
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (OutputBuffer == NULL || OutputLength < sizeof(ULONG))
		return STATUS_BUFFER_TOO_SMALL;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status)) return Status;

	HANDLE hProc = NULL;
	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
		PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProc);
	ObfDereferenceObject(Process);
	if (!NT_SUCCESS(Status)) return Status;

	PULONG Count = (PULONG)OutputBuffer;
	*Count = 0;
	PUCHAR Data = (PUCHAR)(Count + 1);
	ULONG Remain = OutputLength - sizeof(ULONG);

	static const WCHAR* Names[] = { L"DEP", L"ASLR", L"DynamicCode", L"StrictHandle",
		L"SysCallDisable", L"ExtPointDisable", L"CFG", L"Signature",
		L"FontDisable", L"ImageLoad", L"SideChannel", L"ShadowStack",
		L"RedirTrust", L"UserPtrAuth" };
	ULONG NameCount = RTL_NUMBER_OF(Names);

	for (ULONG i = 0; i < NameCount && Remain >= (sizeof(ULONG) * 3 + 64); i++)
	{
		
		UCHAR MitBuf[16] = {};
		*(PULONG)MitBuf = i;
		ULONG RetLen = 0;
		Status = ZwQueryInformationProcess(hProc,
			(PROCESSINFOCLASS)ProcessMitigationPolicy,
			MitBuf, sizeof(MitBuf), &RetLen);

		if (NT_SUCCESS(Status) && RetLen >= 8)
		{
			*(PULONG)Data = i; Data += 4;
			*(PULONG64*)Data = 0; Data += 8;
			ULONG NameLen = (ULONG)(wcslen(Names[i]) * sizeof(WCHAR));
			RtlCopyMemory(Data, Names[i], NameLen);
			Data += 64;
			(*Count)++;
			Remain -= (sizeof(ULONG) * 3 + 64);
		}
	}

	*BytesReturned = (ULONG)(Data - (PUCHAR)OutputBuffer);
	ZwClose(hProc);
	return STATUS_SUCCESS;
}

static NTSTATUS
SetMitigation(
	_In_ PMITIGATION_SET_INPUT Input
)
{
	if (Input == NULL || Input->ProcessId == 0 || Input->ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Input->ProcessId), &Process);
	if (!NT_SUCCESS(Status)) return Status;

	HANDLE hProc = NULL;
	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
		PROCESS_SET_INFORMATION, *PsProcessType, KernelMode, &hProc);
	ObfDereferenceObject(Process);
	if (!NT_SUCCESS(Status)) return Status;

	ULONG64 PolicyValue = Input->Flags;
	Status = ZwSetInformationProcess(hProc,
		(PROCESSINFOCLASS)ProcessMitigationPolicy,
		(PVOID)&PolicyValue, sizeof(ULONG64));

	ZwClose(hProc);

	if (!NT_SUCCESS(Status))
		LogMessage("Mitigation: set %u=0x%llx on PID %u failed 0x%08X.\n",
			Input->PolicyId, Input->Flags, Input->ProcessId, Status);
	else
		LogMessage("Mitigation: set %u=0x%llx on PID %u.\n",
			Input->PolicyId, Input->Flags, Input->ProcessId);

	return Status;
}
