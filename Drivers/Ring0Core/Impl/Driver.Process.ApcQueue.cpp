
static VOID
KernelApcRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);

	ULONG Action = (ULONG)(ULONG_PTR)(SystemArgument1 ? *SystemArgument1 : NULL);

	switch (Action)
	{
	case APC_ACTION_TERMINATE:
		ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
		break;

	default:
		break;
	}

	if (SystemArgument2 != NULL && *SystemArgument2 != NULL)
		ExFreePoolWithTag(*SystemArgument2, POOL_TAG);
}

static VOID
QueueApcFindThread(
	_In_ PEPROCESS Process,
	_Out_ PETHREAD* TargetThread)
{
	*TargetThread = NULL;

	ULONG BufSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		SystemProcessInformation, NULL, 0, &BufSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		return;

	PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
	if (SysBuf == NULL)
		return;

	Status = ZwQuerySystemInformation(
		SystemProcessInformation, SysBuf, BufSize * 2, NULL);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		return;
	}

	ULONG TargetProcessId = (ULONG)(ULONG_PTR)PsGetProcessId(Process);

	PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
	while (TRUE)
	{
		if ((ULONG)(ULONG_PTR)Entry->UniqueProcessId == TargetProcessId)
		{
			if (Entry->NumberOfThreads > 0)
			{
				PMDV_SYSTEM_THREAD_INFORMATION ThreadEntry =
					reinterpret_cast<PMDV_SYSTEM_THREAD_INFORMATION>(
						(PUCHAR)Entry + sizeof(SYSTEM_PROCESS_INFORMATION));

				HANDLE Tid = ThreadEntry->ClientId.UniqueThread;
				if (Tid != NULL)
				{
					PETHREAD Thread = NULL;
					if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &Thread)))
					{
						*TargetThread = Thread;
					}
				}
			}
			break;
		}

		if (Entry->NextEntryOffset == 0)
			break;
		Entry = (PSYSTEM_PROCESS_INFORMATION)
			((PUCHAR)Entry + Entry->NextEntryOffset);
	}

	ExFreePoolWithTag(SysBuf, POOL_TAG);
}

NTSTATUS
QueueProcessApc(
	_In_ ULONG ProcessId,
	_In_ ULONG ApcAction
)
{
	if (ApcAction != APC_ACTION_NOOP && ApcAction != APC_ACTION_TERMINATE)
		return STATUS_NOT_SUPPORTED;

	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("QueueApc: PID %u not found.\n", ProcessId);
		return Status;
	}

	PETHREAD TargetThread = NULL;
	QueueApcFindThread(Process, &TargetThread);

	if (TargetThread == NULL)
	{
		ObfDereferenceObject(Process);
		LogMessage("QueueApc: no threads found for PID %u.\n", ProcessId);
		return STATUS_NOT_FOUND;
	}

	PVOID ApcMem = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG);
	if (ApcMem == NULL)
	{
		ObfDereferenceObject(TargetThread);
		ObfDereferenceObject(Process);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PVOID ActionArg = (PVOID)(ULONG_PTR)ApcAction;
	PVOID FreeArg   = ApcMem;

	KeInitializeApc(
		(PKAPC)ApcMem,
		(PKTHREAD)TargetThread,
		OriginalApcEnvironment,
		KernelApcRoutine,
		NULL,
		NULL,
		KernelMode,
		NULL);

	BOOLEAN Inserted = KeInsertQueueApc(
		(PKAPC)ApcMem,
		ActionArg,
		FreeArg,
		0);

	if (!Inserted)
	{
		ExFreePoolWithTag(ApcMem, POOL_TAG);
		LogMessage("QueueApc: failed to insert APC.\n");
	}
	else
	{
		LogMessage("QueueApc: APC queued to PID %u (action %u).\n", ProcessId, ApcAction);
	}

	ObfDereferenceObject(TargetThread);
	ObfDereferenceObject(Process);
	return Inserted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
