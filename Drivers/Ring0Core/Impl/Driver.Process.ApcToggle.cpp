
static PVOID
QuerySystemProcessSnapshot(
	_Out_ PULONG BufferSize
)
{
	*BufferSize = 0;

	ULONG Required = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		SystemProcessInformation, NULL, 0, &Required);
	if (Status != STATUS_INFO_LENGTH_MISMATCH || Required == 0)
		return NULL;

	ULONG AllocationSize = Required + PAGE_SIZE;
	PVOID Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, AllocationSize, POOL_TAG);
	if (Buffer == NULL)
		return NULL;

	Status = ZwQuerySystemInformation(
		SystemProcessInformation, Buffer, AllocationSize, &Required);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Buffer, POOL_TAG);
		return NULL;
	}

	*BufferSize = AllocationSize;
	return Buffer;
}

static PAPC_TOGGLE_ENTRY
FindApcToggleEntryLocked(
	_In_ ULONG ProcessId,
	_In_ HANDLE ThreadId
)
{
	for (PLIST_ENTRY Link = G_ApcToggleListHead.Flink;
		Link != &G_ApcToggleListHead;
		Link = Link->Flink)
	{
		PAPC_TOGGLE_ENTRY Entry = CONTAINING_RECORD(Link, APC_TOGGLE_ENTRY, ListEntry);
		if (Entry->ProcessId == ProcessId && Entry->ThreadId == ThreadId)
			return Entry;
	}

	return NULL;
}

static ULONG
PurgeApcToggleEntriesLocked(
	_In_ ULONG ProcessId
)
{
	ULONG Removed = 0;
	PLIST_ENTRY Link = G_ApcToggleListHead.Flink;
	while (Link != &G_ApcToggleListHead)
	{
		PLIST_ENTRY Next = Link->Flink;
		PAPC_TOGGLE_ENTRY Entry = CONTAINING_RECORD(Link, APC_TOGGLE_ENTRY, ListEntry);
		if (Entry->ProcessId == ProcessId)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			if (G_ApcToggleCount > 0)
				G_ApcToggleCount--;
			Removed++;
		}
		Link = Next;
	}

	return Removed;
}

static VOID
ClearApcToggleEntries(
	VOID
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
	while (!IsListEmpty(&G_ApcToggleListHead))
	{
		PLIST_ENTRY Link = RemoveHeadList(&G_ApcToggleListHead);
		PAPC_TOGGLE_ENTRY Entry = CONTAINING_RECORD(Link, APC_TOGGLE_ENTRY, ListEntry);
		ExFreePoolWithTag(Entry, POOL_TAG);
		if (G_ApcToggleCount > 0)
			G_ApcToggleCount--;
	}
	KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);
}

NTSTATUS
DisableProcessApc(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	if (!G_KernelApcDisableFound)
	{
		NTSTATUS Status = FindKernelApcDisableOffset(&G_KernelApcDisableOffset);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("DisableApc: cannot resolve KernelApcDisable offset.\n");
			return Status;
		}
		G_KernelApcDisableFound = TRUE;
	}

	ULONG SnapshotSize = 0;
	PVOID Snapshot = QuerySystemProcessSnapshot(&SnapshotSize);
	if (Snapshot == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	ULONG DisabledCount = 0;
	BOOLEAN FoundProcess = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFORMATION Entry =
		reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(Snapshot);
	while (TRUE)
	{
		if ((ULONG)(ULONG_PTR)Entry->UniqueProcessId == ProcessId)
		{
			FoundProcess = TRUE;
			PMDV_SYSTEM_THREAD_INFORMATION Threads =
				reinterpret_cast<PMDV_SYSTEM_THREAD_INFORMATION>(Entry + 1);
			for (ULONG Index = 0; Index < Entry->NumberOfThreads; ++Index)
			{
				const HANDLE ThreadId = Threads[Index].ClientId.UniqueThread;
				if (ThreadId == NULL)
					continue;

				KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
				const BOOLEAN AlreadyTracked =
					FindApcToggleEntryLocked(ProcessId, ThreadId) != NULL;
				KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);
				if (AlreadyTracked)
					continue;

				PETHREAD Thread = NULL;
				Status = PsLookupThreadByThreadId(ThreadId, &Thread);
				if (!NT_SUCCESS(Status))
					continue;

				volatile SHORT* ApcDisable = (volatile SHORT*)
					((PUCHAR)Thread + G_KernelApcDisableOffset);
				SHORT OriginalValue = 0;
				__try
				{
					OriginalValue = *ApcDisable;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
					ObfDereferenceObject(Thread);
					LogMessage("DisableApc: failed to read APC state for TID %u: 0x%08X\n",
						HandleToULong(ThreadId), Status);
					goto DisableDone;
				}

				if (OriginalValue < 0)
				{
					ObfDereferenceObject(Thread);
					continue;
				}

				PAPC_TOGGLE_ENTRY ToggleEntry = (PAPC_TOGGLE_ENTRY)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(APC_TOGGLE_ENTRY), POOL_TAG);
				if (ToggleEntry == NULL)
				{
					ObfDereferenceObject(Thread);
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto DisableDone;
				}

				RtlZeroMemory(ToggleEntry, sizeof(*ToggleEntry));
				ToggleEntry->ProcessId = ProcessId;
				ToggleEntry->ThreadId = ThreadId;
				ToggleEntry->OriginalKernelApcDisable = OriginalValue;
				ToggleEntry->Active = TRUE;

				KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
				if (FindApcToggleEntryLocked(ProcessId, ThreadId) != NULL)
				{
					KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);
					ExFreePoolWithTag(ToggleEntry, POOL_TAG);
					ObfDereferenceObject(Thread);
					continue;
				}
				InsertTailList(&G_ApcToggleListHead, &ToggleEntry->ListEntry);
				G_ApcToggleCount++;
				KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);

				__try
				{
					*ApcDisable = -1;
					DisabledCount++;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
					KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
					RemoveEntryList(&ToggleEntry->ListEntry);
					if (G_ApcToggleCount > 0)
						G_ApcToggleCount--;
					KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);
					ExFreePoolWithTag(ToggleEntry, POOL_TAG);
					ObfDereferenceObject(Thread);
					LogMessage("DisableApc: failed to write APC state for TID %u: 0x%08X\n",
						HandleToULong(ThreadId), Status);
					goto DisableDone;
				}

				ObfDereferenceObject(Thread);
			}
			break;
		}

		if (Entry->NextEntryOffset == 0)
			break;
		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
			reinterpret_cast<PUCHAR>(Entry) + Entry->NextEntryOffset);
	}

DisableDone:
	ExFreePoolWithTag(Snapshot, POOL_TAG);
	if (!FoundProcess && NT_SUCCESS(Status))
		Status = STATUS_NOT_FOUND;
	LogMessage("DisableApc: PID %u, %u threads blocked.\n", ProcessId, DisabledCount);
	return Status;
}

NTSTATUS
EnableProcessApc(
	_In_ ULONG ProcessId
)
{
	KIRQL LockIrql;

	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	if (!G_KernelApcDisableFound)
	{
		NTSTATUS Status = FindKernelApcDisableOffset(&G_KernelApcDisableOffset);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("EnableApc: cannot resolve KernelApcDisable offset.\n");
			return Status;
		}
		G_KernelApcDisableFound = TRUE;
	}

	ULONG SnapshotSize = 0;
	PVOID Snapshot = QuerySystemProcessSnapshot(&SnapshotSize);
	if (Snapshot == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	ULONG EnabledCount = 0;
	BOOLEAN FoundProcess = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFORMATION Entry =
		reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(Snapshot);
	while (TRUE)
	{
		if ((ULONG)(ULONG_PTR)Entry->UniqueProcessId == ProcessId)
		{
			FoundProcess = TRUE;
			PMDV_SYSTEM_THREAD_INFORMATION Threads =
				reinterpret_cast<PMDV_SYSTEM_THREAD_INFORMATION>(Entry + 1);
			for (ULONG Index = 0; Index < Entry->NumberOfThreads; ++Index)
			{
				const HANDLE ThreadId = Threads[Index].ClientId.UniqueThread;
				if (ThreadId == NULL)
					continue;

				KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
				PAPC_TOGGLE_ENTRY ToggleEntry = FindApcToggleEntryLocked(ProcessId, ThreadId);
				if (ToggleEntry != NULL)
				{
					RemoveEntryList(&ToggleEntry->ListEntry);
					if (G_ApcToggleCount > 0)
						G_ApcToggleCount--;
				}
				KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);

				if (ToggleEntry == NULL)
					continue;

				PETHREAD Thread = NULL;
				Status = PsLookupThreadByThreadId(ThreadId, &Thread);
				if (NT_SUCCESS(Status))
				{
					volatile SHORT* ApcDisable = (volatile SHORT*)
						((PUCHAR)Thread + G_KernelApcDisableOffset);
					__try
					{
						*ApcDisable = ToggleEntry->OriginalKernelApcDisable;
						EnabledCount++;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
						LogMessage("EnableApc: failed to restore APC state for TID %u: 0x%08X\n",
							HandleToULong(ThreadId), Status);
					}
					ObfDereferenceObject(Thread);
				}

				ExFreePoolWithTag(ToggleEntry, POOL_TAG);
			}
			break;
		}

		if (Entry->NextEntryOffset == 0)
			break;
		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
			reinterpret_cast<PUCHAR>(Entry) + Entry->NextEntryOffset);
	}

	ExFreePoolWithTag(Snapshot, POOL_TAG);
	if (!FoundProcess && NT_SUCCESS(Status))
	{
		KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
		(void)PurgeApcToggleEntriesLocked(ProcessId);
		KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);
		Status = STATUS_NOT_FOUND;
	}

	KeAcquireSpinLock(&G_ApcToggleListLock, &LockIrql);
	const ULONG PurgedCount = PurgeApcToggleEntriesLocked(ProcessId);
	KeReleaseSpinLock(&G_ApcToggleListLock, LockIrql);

	LogMessage("EnableApc: PID %u, %u threads restored, %u stale records purged.\n",
		ProcessId, EnabledCount, PurgedCount);
	return Status;
}