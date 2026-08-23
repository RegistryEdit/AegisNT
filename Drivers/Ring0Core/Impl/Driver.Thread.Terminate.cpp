
NTSTATUS
ForceTerminateThread(
	_In_ ULONG ThreadId,
	_In_ ULONG ProcessId
)
{
	if (ThreadId == 0 || ProcessId == 0)
		return STATUS_INVALID_PARAMETER;

	PETHREAD Thread = NULL;
	NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("ForceTerminateThread: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		return Status;
	}

	PEPROCESS Owner = IoThreadToProcess(Thread);
	if (Owner == NULL || PsGetProcessId(Owner) != ULongToHandle(ProcessId))
	{
		ObfDereferenceObject(Thread);
		LogMessage("ForceTerminateThread: TID %u owner mismatch.\n", ThreadId);
		return STATUS_INVALID_CID;
	}

	ULONG_PTR KernelBase = 0;
	ULONG KernelSize = 0;
	BOOLEAN KernelInfoValid = GetNtoskrnlInfo(&KernelBase, &KernelSize);

	{
		UNICODE_STRING PsTermName;
		RtlInitUnicodeString(&PsTermName, L"PsTerminateSystemThread");
		PVOID PsTermAddr = MmGetSystemRoutineAddress(&PsTermName);

		if (PsTermAddr != NULL && KernelInfoValid)
		{
			for (ULONG Off = 0; Off < 128; ++Off)
			{
				PUCHAR Code = (PUCHAR)PsTermAddr + Off;
				if (Code[0] == 0xE8)
				{
					LONG Rel32 = *(PLONG)(Code + 1);
					PVOID Target = (PVOID)((ULONG_PTR)Code + 5 + Rel32);

					if ((ULONG_PTR)Target >= KernelBase &&
						(ULONG_PTR)Target < KernelBase + KernelSize)
					{
						typedef NTSTATUS(NTAPI* PPspTerminateByPtr_t)(PETHREAD, NTSTATUS);
						Status = ((PPspTerminateByPtr_t)Target)(Thread, STATUS_SUCCESS);
						if (NT_SUCCESS(Status))
						{
							ObfDereferenceObject(Thread);
							LogMessage("ForceTerminateThread: TID %u terminated via PspTerminateThreadByPointer.\n",
								ThreadId);
							return Status;
						}
						LogMessage("ForceTerminateThread: PspTerminateThreadByPointer(TID=%u) failed 0x%08X, trying ZwTerminateThread...\n",
							ThreadId, Status);
						break;
					}
				}
			}
		}
	}

	HANDLE ThreadHandle = NULL;
	CLIENT_ID ClientId = { ULongToHandle(ProcessId), ULongToHandle(ThreadId) };
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(
		(PUNICODE_STRING)NULL, OBJ_KERNEL_HANDLE);

	Status = ZwOpenThread(&ThreadHandle,
		THREAD_TERMINATE | SYNCHRONIZE | THREAD_QUERY_INFORMATION,
		&ObjectAttributes, &ClientId);
	if (!NT_SUCCESS(Status))
	{
		ObfDereferenceObject(Thread);
		LogMessage("ForceTerminateThread: ZwOpenThread(TID=%u, PID=%u) failed: 0x%08X.\n",
			ThreadId, ProcessId, Status);
		return Status;
	}

	PVOID TerminateAddr = NULL;
	if (KernelInfoValid)
	{
		__try
		{
			PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)KernelBase;
			if (Dos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(KernelBase + Dos->e_lfanew);
				if (NtHdr->Signature == IMAGE_NT_SIGNATURE)
				{
					IMAGE_DATA_DIRECTORY ExpDir =
						NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
					if (ExpDir.VirtualAddress != 0 && ExpDir.Size != 0)
					{
						PIMAGE_EXPORT_DIRECTORY Exports =
							(PIMAGE_EXPORT_DIRECTORY)(KernelBase + ExpDir.VirtualAddress);
						PULONG Names = (PULONG)(KernelBase + Exports->AddressOfNames);
						PUSHORT Ordinals = (PUSHORT)(KernelBase + Exports->AddressOfNameOrdinals);
						PULONG Functions = (PULONG)(KernelBase + Exports->AddressOfFunctions);
						PCSTR Target = "NtTerminateThread";
						SIZE_T TargetLen = 18;

						for (ULONG i = 0; i < Exports->NumberOfNames; ++i)
						{
							PCSTR Name = (PCSTR)(KernelBase + Names[i]);
							if (RtlCompareMemory(Name, Target, TargetLen) == TargetLen &&
								Name[TargetLen] == '\0')
							{
								TerminateAddr = (PVOID)(KernelBase + Functions[Ordinals[i]]);
								break;
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

	if (TerminateAddr == NULL)
	{
		ZwClose(ThreadHandle);
		ObfDereferenceObject(Thread);
		LogMessage("ForceTerminateThread: NtTerminateThread not found in ntoskrnl exports.\n");
		return STATUS_NOT_FOUND;
	}

	typedef NTSTATUS(NTAPI* PZwTerminateThread_t)(HANDLE, NTSTATUS);
	Status = ((PZwTerminateThread_t)TerminateAddr)(ThreadHandle, STATUS_SUCCESS);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(ThreadHandle);
		ObfDereferenceObject(Thread);
		LogMessage("ForceTerminateThread: ZwTerminateThread(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		return Status;
	}

	UNICODE_STRING WaitName;
	RtlInitUnicodeString(&WaitName, L"ZwWaitForSingleObject");
	PVOID WaitAddr = MmGetSystemRoutineAddress(&WaitName);
	if (WaitAddr != NULL)
	{
		typedef NTSTATUS(NTAPI* PZwWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
		LARGE_INTEGER Timeout = {};
		Timeout.QuadPart = -(10LL * 1000 * 500);
		Status = ((PZwWaitForSingleObject_t)WaitAddr)(
			ThreadHandle, FALSE, &Timeout);
		if (!NT_SUCCESS(Status))
		{
			ZwClose(ThreadHandle);
			ObfDereferenceObject(Thread);
			LogMessage("ForceTerminateThread: wait for TID %u failed: 0x%08X.\n",
				ThreadId, Status);
			return Status;
		}
	}

	ZwClose(ThreadHandle);
	ObfDereferenceObject(Thread);
	LogMessage("ForceTerminateThread: TID %u in PID %u terminated via ZwTerminateThread.\n",
		ThreadId, ProcessId);
	return STATUS_SUCCESS;
}
