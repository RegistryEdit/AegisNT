
NTSTATUS
AdjustProcessPrivileges(
	_In_ ULONG   ProcessId,
	_In_ PLUID   PrivilegeLuid,
	_In_ BOOLEAN Enable
)
{
	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("AdjustPrivileges: PID %u not found.\n", ProcessId);
		return Status;
	}

	HANDLE hProcess = NULL;
	Status = ObOpenObjectByPointer(
		Process,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&hProcess);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("AdjustPrivileges: ObOpenObjectByPointer failed 0x%08X.\n", Status);
		ObfDereferenceObject(Process);
		return Status;
	}

	HANDLE hToken = NULL;
	Status = ZwOpenProcessTokenEx(
		hProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		OBJ_KERNEL_HANDLE,
		&hToken);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("AdjustPrivileges: ZwOpenProcessTokenEx failed 0x%08X.\n", Status);
		ZwClose(hProcess);
		ObfDereferenceObject(Process);
		return Status;
	}

	TOKEN_PRIVILEGES Tp = { 0 };
	Tp.PrivilegeCount = 1;
	Tp.Privileges[0].Luid = *PrivilegeLuid;
	Tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

	Status = ZwAdjustPrivilegesToken(hToken, FALSE, &Tp, sizeof(Tp), NULL, NULL);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("AdjustPrivileges: ZwAdjustPrivilegesToken failed 0x%08X.\n", Status);
	}
	else
	{
		LogMessage("PID %u privilege LUID %08X-%08X %s.\n",
			ProcessId,
			PrivilegeLuid->HighPart,
			PrivilegeLuid->LowPart,
			Enable ? "enabled" : "disabled");
	}

	ZwClose(hToken);
	ZwClose(hProcess);
	ObfDereferenceObject(Process);
	return Status;
}
