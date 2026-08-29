
NTSTATUS
ForceTerminateProcess(
	_In_ ULONG ProcessId
)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;

	UNICODE_STRING RoutineName;
	RtlInitUnicodeString(&RoutineName, L"PspTerminateProcess");
	PVOID PspTerminateProcessAddr = MmGetSystemRoutineAddress(&RoutineName);

	if (PspTerminateProcessAddr != NULL)
	{
		Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
		if (NT_SUCCESS(Status))
		{
			typedef NTSTATUS(*PspTerminateProcess_t)(PEPROCESS, NTSTATUS);
			PspTerminateProcess_t PspTerminateProcessFn =
				reinterpret_cast<PspTerminateProcess_t>(PspTerminateProcessAddr);

			LogMessage("Terminating PID %u via PspTerminateProcess.\n", ProcessId);
			Status = PspTerminateProcessFn(Process, STATUS_SUCCESS);
			ObfDereferenceObject(Process);
			return Status;
		}
	}

	HANDLE ProcessHandle = NULL;
	CLIENT_ID ClientId = { ULongToHandle(ProcessId), NULL };
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, OBJ_KERNEL_HANDLE);

	Status = ZwOpenProcess(
		&ProcessHandle,
		PROCESS_TERMINATE,
		&ObjectAttributes,
		&ClientId);

	if (NT_SUCCESS(Status))
	{
		LogMessage("Terminating PID %u via ZwTerminateProcess.\n", ProcessId);
		Status = ZwTerminateProcess(ProcessHandle, STATUS_SUCCESS);
		ZwClose(ProcessHandle);
		return Status;
	}

	Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (NT_SUCCESS(Status))
	{
		LogMessage("Terminating PID %u via EPROCESS zeroing.\n", ProcessId);

#ifdef _M_AMD64
		PCHAR ProcessBase = reinterpret_cast<PCHAR>(Process) + EPROCESS_SCAN_START;
		CONST ULONG EndOffset = ALIGN_UP_BY(Process, PAGE_SIZE) -
			reinterpret_cast<ULONG_PTR>(Process);
		for (ULONG i = 0; i < EndOffset - EPROCESS_SCAN_START - sizeof(ULONG); i++)
		{
			if (*reinterpret_cast<PULONG>(ProcessBase + i) ==
				HandleToULong(PsGetProcessId(Process)))
			{
				RtlZeroMemory(ProcessBase + i, sizeof(ULONG));
				break;
			}
		}
#endif

		ObfDereferenceObject(Process);
		return STATUS_SUCCESS;
	}

	LogMessage("ForceTerminateProcess: all methods failed for PID %u (0x%08X).\n",
		ProcessId, Status);
	return Status;
}

NTSTATUS
ForceTerminateProcessThreads(
	_In_ ULONG ProcessId,
	_Out_ PTERMINATE_PROCESS_THREADS_OUTPUT Output
)
{
	if (Output == NULL)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Output, sizeof(*Output));
	Output->ProcessId = ProcessId;
	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	//
	// Enumerate the target process's threads via the system process
	// information snapshot. This avoids the dependency on
	// PsGetNextProcessThread, which is not exported on every Windows
	// build and previously caused the enumeration to fail (0 threads).
	//
	ULONG BufSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		SystemProcessInformation, NULL, 0, &BufSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		return Status;

	PVOID SysBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize * 2, POOL_TAG);
	if (SysBuf == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	Status = ZwQuerySystemInformation(
		SystemProcessInformation, SysBuf, BufSize * 2, NULL);
	if (!NT_SUCCESS(Status)) {
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		return Status;
	}

	ULONG Capacity = 32;
	PULONG ThreadIds = static_cast<PULONG>(ExAllocatePool2(
		POOL_FLAG_NON_PAGED, Capacity * sizeof(ULONG), POOL_TAG));
	if (ThreadIds == NULL) {
		ExFreePoolWithTag(SysBuf, POOL_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG ThreadCount = 0;
	BOOLEAN Found = FALSE;
	PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)SysBuf;
	while (TRUE) {
		if ((ULONG)(ULONG_PTR)Entry->UniqueProcessId == ProcessId) {
			Found = TRUE;
			PMDV_SYSTEM_THREAD_INFORMATION Threads =
				reinterpret_cast<PMDV_SYSTEM_THREAD_INFORMATION>(Entry + 1);
			for (ULONG i = 0; i < Entry->NumberOfThreads; ++i) {
				const ULONG ThreadId =
					(ULONG)(ULONG_PTR)Threads[i].ClientId.UniqueThread;
				if (ThreadId == 0)
					continue;

				if (ThreadCount == Capacity) {
					const ULONG NewCapacity = Capacity * 2;
					PULONG NewThreadIds = static_cast<PULONG>(ExAllocatePool2(
						POOL_FLAG_NON_PAGED, NewCapacity * sizeof(ULONG), POOL_TAG));
					if (NewThreadIds == NULL)
						break;
					RtlCopyMemory(NewThreadIds, ThreadIds, ThreadCount * sizeof(ULONG));
					ExFreePoolWithTag(ThreadIds, POOL_TAG);
					ThreadIds = NewThreadIds;
					Capacity = NewCapacity;
				}
				ThreadIds[ThreadCount++] = ThreadId;
			}
			break;
		}
		if (Entry->NextEntryOffset == 0)
			break;
		Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
	}

	ExFreePoolWithTag(SysBuf, POOL_TAG);

	if (!Found) {
		ExFreePoolWithTag(ThreadIds, POOL_TAG);
		return STATUS_NOT_FOUND;
	}

	Output->EnumeratedCount = ThreadCount;
	NTSTATUS LastStatus = STATUS_SUCCESS;
	for (ULONG Index = 0; Index < ThreadCount; ++Index)
	{
		const NTSTATUS ThreadStatus =
			ForceTerminateThread(ThreadIds[Index], ProcessId);
		if (NT_SUCCESS(ThreadStatus))
			Output->TerminatedCount++;
		else
		{
			Output->FailedCount++;
			LastStatus = ThreadStatus;
		}
	}

	ExFreePoolWithTag(ThreadIds, POOL_TAG);
	if (Output->EnumeratedCount == 0)
		LastStatus = STATUS_NOT_FOUND;
	Output->LastStatus = LastStatus;
	LogMessage("ForceTerminateProcessThreads: PID %u enumerated=%u terminated=%u failed=%u.\n",
		ProcessId, Output->EnumeratedCount, Output->TerminatedCount,
		Output->FailedCount);
	return STATUS_SUCCESS;
}

NTSTATUS
ZeroProcessPrivateMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PEPROCESS TargetEProcess
)
{
	if (ProcessHandle == NULL || TargetEProcess == NULL)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS FirstFailure = STATUS_SUCCESS;
	ULONG_PTR Address = 0;
	SIZE_T ZeroedBytes = 0;

	while (Address < reinterpret_cast<ULONG_PTR>(MmHighestUserAddress))
	{
		MEMORY_BASIC_INFORMATION Info = {};
		SIZE_T ReturnedLength = 0;
		NTSTATUS Status = ZwQueryVirtualMemory(
			ProcessHandle,
			reinterpret_cast<PVOID>(Address),
			MemoryBasicInformation,
			&Info,
			sizeof(Info),
			&ReturnedLength);
		if (!NT_SUCCESS(Status))
		{
			if (Status != STATUS_INVALID_ADDRESS && NT_SUCCESS(FirstFailure))
				FirstFailure = Status;
			break;
		}

		const ULONG_PTR RegionBase =
			reinterpret_cast<ULONG_PTR>(Info.BaseAddress);
		const ULONG_PTR RegionEnd = RegionBase + Info.RegionSize;
		if (Info.RegionSize == 0 || RegionEnd <= RegionBase)
		{
			if (NT_SUCCESS(FirstFailure))
				FirstFailure = STATUS_INVALID_ADDRESS;
			break;
		}

		if (Info.State == MEM_COMMIT &&
			Info.Type == MEM_PRIVATE &&
			(Info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0)
		{
			for (ULONG_PTR PageAddress = RegionBase;
				PageAddress < RegionEnd;
				PageAddress += PAGE_SIZE)
			{
				const SIZE_T BytesThisPage = min(
					static_cast<SIZE_T>(PAGE_SIZE),
					static_cast<SIZE_T>(RegionEnd - PageAddress));
				PMDL Mdl = IoAllocateMdl(
					reinterpret_cast<PVOID>(PageAddress),
					static_cast<ULONG>(BytesThisPage),
					FALSE,
					FALSE,
					NULL);
				if (Mdl == NULL)
				{
					if (NT_SUCCESS(FirstFailure))
						FirstFailure = STATUS_INSUFFICIENT_RESOURCES;
					continue;
				}

				KAPC_STATE ApcState;
				BOOLEAN PagesLocked = FALSE;
				PVOID MappedAddress = NULL;
				KeStackAttachProcess(TargetEProcess, &ApcState);
				__try
				{
					MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
					PagesLocked = TRUE;
					MappedAddress = MmMapLockedPagesSpecifyCache(
						Mdl,
						KernelMode,
						MmCached,
						NULL,
						FALSE,
						NormalPagePriority | MdlMappingNoExecute);
					if (MappedAddress == NULL)
					{
						if (NT_SUCCESS(FirstFailure))
							FirstFailure = STATUS_INSUFFICIENT_RESOURCES;
					}
					else
					{
						RtlZeroMemory(MappedAddress, BytesThisPage);
						ZeroedBytes += BytesThisPage;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					if (NT_SUCCESS(FirstFailure))
						FirstFailure = GetExceptionCode();
				}
				KeUnstackDetachProcess(&ApcState);

				if (MappedAddress != NULL)
					MmUnmapLockedPages(MappedAddress, Mdl);
				if (PagesLocked)
					MmUnlockPages(Mdl);
				IoFreeMdl(Mdl);
			}
		}

		Address = RegionEnd;
	}

	LogMessage("ZeroProcessPrivateMemory: zeroed %llu bytes (status 0x%08X).\n",
		static_cast<unsigned long long>(ZeroedBytes), FirstFailure);
	return FirstFailure;
}

NTSTATUS
WriteZeroMemoryToProcess(
	_In_ ULONG ProcessId
)
{
	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	PEPROCESS TargetProcess = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &TargetProcess);
	if (!NT_SUCCESS(Status))
		return Status;

	HANDLE HProcess = NULL;
	Status = ObOpenObjectByPointer(
		TargetProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&HProcess);
	if (NT_SUCCESS(Status))
	{
		Status = ZeroProcessPrivateMemory(HProcess, TargetProcess);
		ZwClose(HProcess);
	}
	ObfDereferenceObject(TargetProcess);
	return Status;
}
