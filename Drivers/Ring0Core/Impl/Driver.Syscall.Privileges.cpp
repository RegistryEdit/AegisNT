#define KTHREAD_PREVIOUSMODE_OFFSET  0x232

typedef PETHREAD (NTAPI *PMdvPsGetNextProcessThread_t)(
	_In_ PEPROCESS Process,
	_In_opt_ PETHREAD Thread
	);

static PMdvPsGetNextProcessThread_t G_pPsGetNextProcessThread = NULL;

NTSTATUS
SetProcessPreviousMode(
	_In_ ULONG ProcessId
)
{
	if (ProcessId == 0 || ProcessId == 4)
		return STATUS_ACCESS_DENIED;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	if (!NT_SUCCESS(Status))
		return Status;

	if (G_pPsGetNextProcessThread == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"PsGetNextProcessThread");
		G_pPsGetNextProcessThread = (PMdvPsGetNextProcessThread_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pPsGetNextProcessThread == NULL)
	{
		ObDereferenceObject(Process);
		LogMessage("PsGetNextProcessThread unavailable, cannot set PreviousMode.\n");
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	ULONG Count = 0;
	PETHREAD Thread = NULL;
	while ((Thread = G_pPsGetNextProcessThread(Process, Thread)) != NULL)
	{
		PUCHAR ThreadBase = (PUCHAR)Thread;
		*(ThreadBase + KTHREAD_PREVIOUSMODE_OFFSET) = 0;
		Count++;
	}

	ObDereferenceObject(Process);

	LogMessage("Set KernelMode PreviousMode for %lu threads in PID %lu\n", Count, ProcessId);
	return STATUS_SUCCESS;
}
