
typedef ULONG    (NTAPI *PFN_SUSPEND_T)(PETHREAD, PULONG);
typedef ULONG    (NTAPI *PFN_RESUME_T)(PETHREAD, PULONG);
typedef NTSTATUS (NTAPI *PFN_GETCTX_T)(PETHREAD, PCONTEXT, KPROCESSOR_MODE);
typedef NTSTATUS (NTAPI *PFN_SETCTX_T)(PETHREAD, PCONTEXT, KPROCESSOR_MODE);

static PFN_SUSPEND_T G_pPsSuspend = NULL;
static PFN_RESUME_T  G_pPsResume  = NULL;
static PFN_GETCTX_T  G_pPsGetCtx  = NULL;
static PFN_SETCTX_T  G_pPsSetCtx  = NULL;

static VOID
HijackInitApis(VOID)
{
	if (G_pPsSuspend) return;
	UNICODE_STRING u;
	RtlInitUnicodeString(&u, L"PsSuspendThread");     G_pPsSuspend = (PFN_SUSPEND_T)MmGetSystemRoutineAddress(&u);
	RtlInitUnicodeString(&u, L"PsResumeThread");      G_pPsResume  = (PFN_RESUME_T) MmGetSystemRoutineAddress(&u);
	RtlInitUnicodeString(&u, L"PsGetContextThread");   G_pPsGetCtx  = (PFN_GETCTX_T) MmGetSystemRoutineAddress(&u);
	RtlInitUnicodeString(&u, L"PsSetContextThread");   G_pPsSetCtx  = (PFN_SETCTX_T) MmGetSystemRoutineAddress(&u);
}

static PUINT64
FindTrapFrameCsSlot(
	_In_ PKTHREAD KThread
)
{
	PKTHREAD K = reinterpret_cast<PKTHREAD>(KThread);

	PVOID StackBase = *(PVOID*)((PUCHAR)K + 0x28);
	PVOID StackLimit = *(PVOID*)((PUCHAR)K + 0x30);
	if (StackBase == NULL || StackLimit == NULL)
		return NULL;

	PUINT64 End = reinterpret_cast<PUINT64>(StackBase) - 5;
	if (reinterpret_cast<PUINT64>(StackLimit) >= reinterpret_cast<PUINT64>(End))
		return NULL;

	for (PUINT64 Ptr = reinterpret_cast<PUINT64>(StackLimit); Ptr < End; Ptr++)
	{
		if (*Ptr != 0x33)
			continue;

		UINT64 Rip = Ptr[-1];
		UINT64 Rsp = Ptr[2];

		if (Rip == 0 || Rip > 0x00007FFFFFFFFFFFULL)
			continue;
		if (Rsp > 0x00007FFFFFFFFFFFULL)
			continue;

		return Ptr;
	}

	return NULL;
}

NTSTATUS
HijackThreadContext(
	_In_ ULONG     ThreadId,
	_In_ ULONG_PTR TargetRip
)
{
	if (ThreadId == 0 || TargetRip == 0)
		return STATUS_INVALID_PARAMETER;

	HijackInitApis();
	if (G_pPsSuspend == NULL || G_pPsResume == NULL ||
		G_pPsGetCtx == NULL || G_pPsSetCtx == NULL)
	{
		LogMessage("HijackContext: PsThread APIs unavailable, falling back to direct TrapFrame hijack for TID=%u.\n",
			ThreadId);
		goto FallbackTrapFrame;
	}

	{
		PETHREAD Thread = NULL;
		NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("HijackContext: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
				ThreadId, Status);
			return Status;
		}

		ULONG PreviousCount;
		Status = G_pPsSuspend(Thread, &PreviousCount);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("HijackContext: PsSuspendThread(TID=%u) failed: 0x%08X.\n",
				ThreadId, Status);
			ObfDereferenceObject(Thread);
			return Status;
		}

		CONTEXT Ctx = { 0 };
		Ctx.ContextFlags = CONTEXT_FULL;
		Status = G_pPsGetCtx(Thread, &Ctx, KernelMode);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("HijackContext: PsGetContextThread(TID=%u) failed: 0x%08X.\n",
				ThreadId, Status);
			G_pPsResume(Thread, NULL);
			ObfDereferenceObject(Thread);
			return Status;
		}

		LogMessage("HijackContext: TID=%u old RIP=%p RSP=%p -> new RIP=%p\n",
			ThreadId, reinterpret_cast<PVOID>(Ctx.Rip),
			reinterpret_cast<PVOID>(Ctx.Rsp), reinterpret_cast<PVOID>(TargetRip));

		Ctx.Rip = TargetRip;

		Status = G_pPsSetCtx(Thread, &Ctx, KernelMode);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("HijackContext: PsSetContextThread(TID=%u) failed: 0x%08X.\n",
				ThreadId, Status);
			G_pPsResume(Thread, NULL);
			ObfDereferenceObject(Thread);
			return Status;
		}

		G_pPsResume(Thread, NULL);
		ObfDereferenceObject(Thread);

		LogMessage("HijackContext: TID=%u resumed, will execute at RIP=%p (Suspend+CONTEXT path).\n",
			ThreadId, reinterpret_cast<PVOID>(TargetRip));

		return STATUS_SUCCESS;
	}

FallbackTrapFrame:
	{
		PETHREAD Thread = NULL;
		NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("HijackContext: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
				ThreadId, Status);
			return Status;
		}

		UCHAR State = *(PUCHAR)((PUCHAR)Thread + 0x84);
		if (State != 5)
		{
			LogMessage("HijackContext: TID=%u not in Waiting state (state=%u), cannot fallback.\n",
				ThreadId, State);
			ObfDereferenceObject(Thread);
			return STATUS_UNSUCCESSFUL;
		}

		PKTHREAD KThread = reinterpret_cast<PKTHREAD>(Thread);
		PUINT64 CsSlot = FindTrapFrameCsSlot(KThread);
		if (CsSlot == NULL)
		{
			LogMessage("HijackContext: could not locate CS=0x33 TrapFrame for TID=%u (kernel stack scan failed).\n",
				ThreadId);
			ObfDereferenceObject(Thread);
			return STATUS_UNSUCCESSFUL;
		}

		UINT64 OldRip = CsSlot[-1];
		LogMessage("HijackContext: TID=%u CS slot at %p, RIP %p -> %p, RSP %p (fallback path).\n",
			ThreadId, CsSlot, reinterpret_cast<PVOID>(OldRip),
			reinterpret_cast<PVOID>(TargetRip), reinterpret_cast<PVOID>(CsSlot[2]));

		CsSlot[-1] = TargetRip;

		ObfDereferenceObject(Thread);

		LogMessage("HijackContext: TID=%u hijacked via TrapFrame, will return to RIP=%p.\n",
			ThreadId, reinterpret_cast<PVOID>(TargetRip));

		return STATUS_SUCCESS;
	}
}

NTSTATUS
HijackThreadTrapFrame(
	_In_ ULONG     ThreadId,
	_In_ ULONG_PTR TargetRip
)
{
	if (ThreadId == 0 || TargetRip == 0)
		return STATUS_INVALID_PARAMETER;

	PETHREAD Thread = NULL;
	NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("HijackTrapFrame: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		return Status;
	}

	UCHAR State = *(PUCHAR)((PUCHAR)Thread + 0x84);
	if (State != 5)
	{
		LogMessage("HijackTrapFrame: TID=%u not in Waiting state (state=%u).\n",
			ThreadId, State);
		ObfDereferenceObject(Thread);
		return STATUS_UNSUCCESSFUL;
	}

	PKTHREAD KThread = reinterpret_cast<PKTHREAD>(Thread);
	PUINT64 CsSlot = FindTrapFrameCsSlot(KThread);
	if (CsSlot == NULL)
	{
		LogMessage("HijackTrapFrame: could not locate CS=0x33 TrapFrame for TID=%u (kernel stack scan failed).\n",
			ThreadId);
		ObfDereferenceObject(Thread);
		return STATUS_UNSUCCESSFUL;
	}

	UINT64 OldRip = CsSlot[-1];
	LogMessage("HijackTrapFrame: TID=%u CS slot at %p, RIP %p -> %p, RSP %p\n",
		ThreadId, CsSlot, reinterpret_cast<PVOID>(OldRip),
		reinterpret_cast<PVOID>(TargetRip), reinterpret_cast<PVOID>(CsSlot[2]));

	CsSlot[-1] = TargetRip;

	ObfDereferenceObject(Thread);

	LogMessage("HijackTrapFrame: TID=%u will return to RIP=%p.\n",
		ThreadId, reinterpret_cast<PVOID>(TargetRip));

	return STATUS_SUCCESS;
}

typedef struct _REMOTE_CALL_APC_CTX {
	KAPC        Apc;
	KEVENT      Event;
	ULONG_PTR   Function;
	ULONG_PTR   Args[4];
	NTSTATUS    Result;
} REMOTE_CALL_APC_CTX, *PREMOTE_CALL_APC_CTX;

static VOID
RemoteCallKernelApc(
	_In_     PKAPC              Apc,
	_Inout_  PKNORMAL_ROUTINE*  NormalRoutine,
	_Inout_  PVOID*             NormalContext,
	_Inout_  PVOID*             SystemArgument1,
	_Inout_  PVOID*             SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PREMOTE_CALL_APC_CTX Ctx = CONTAINING_RECORD(Apc, REMOTE_CALL_APC_CTX, Apc);
	typedef NTSTATUS (NTAPI *PRemoteCallFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

	__try
	{
		Ctx->Result = reinterpret_cast<PRemoteCallFn>(Ctx->Function)(
			Ctx->Args[0], Ctx->Args[1], Ctx->Args[2], Ctx->Args[3]);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Ctx->Result = STATUS_ACCESS_VIOLATION;
	}

	KeSetEvent(&Ctx->Event, IO_NO_INCREMENT, FALSE);
}

static VOID
RemoteCallApcRundown(
	_In_ PKAPC Apc
)
{
	PREMOTE_CALL_APC_CTX Ctx = CONTAINING_RECORD(Apc, REMOTE_CALL_APC_CTX, Apc);
	Ctx->Result = STATUS_CANCELLED;
	KeSetEvent(&Ctx->Event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
RemoteCallInThread(
	_In_  ULONG     ThreadId,
	_In_  ULONG_PTR Function,
	_In_  ULONG_PTR Arg1,
	_In_  ULONG_PTR Arg2,
	_In_  ULONG_PTR Arg3,
	_In_  ULONG_PTR Arg4,
	_Out_ PNTSTATUS OutResult
)
{
	if (ThreadId == 0 || Function == 0 || OutResult == NULL)
		return STATUS_INVALID_PARAMETER;

	PETHREAD Thread = NULL;
	NTSTATUS Status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &Thread);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("RemoteCall: PsLookupThreadByThreadId(TID=%u) failed: 0x%08X.\n",
			ThreadId, Status);
		return Status;
	}

	PREMOTE_CALL_APC_CTX Ctx = static_cast<PREMOTE_CALL_APC_CTX>(
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REMOTE_CALL_APC_CTX), 'lcRH'));
	if (Ctx == NULL)
	{
		ObfDereferenceObject(Thread);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(Ctx, sizeof(REMOTE_CALL_APC_CTX));
	Ctx->Function = Function;
	Ctx->Args[0]  = Arg1;
	Ctx->Args[1]  = Arg2;
	Ctx->Args[2]  = Arg3;
	Ctx->Args[3]  = Arg4;
	Ctx->Result   = STATUS_PENDING;

	KeInitializeEvent(&Ctx->Event, NotificationEvent, FALSE);

	KeInitializeApc(
		&Ctx->Apc,
		reinterpret_cast<PKTHREAD>(Thread),
		OriginalApcEnvironment,
		RemoteCallKernelApc,
		RemoteCallApcRundown,
		NULL,			
		KernelMode,
		Ctx);

	if (!KeInsertQueueApc(&Ctx->Apc, NULL, NULL, 0))
	{
		ExFreePoolWithTag(Ctx, 'lcRH');
		ObfDereferenceObject(Thread);
		LogMessage("RemoteCall: KeInsertQueueApc(TID=%u) failed.\n", ThreadId);
		return STATUS_UNSUCCESSFUL;
	}

	ObfDereferenceObject(Thread);

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -5 * 10000000LL;	

	Status = KeWaitForSingleObject(
		&Ctx->Event,
		Executive,
		KernelMode,
		FALSE,
		&Timeout);

	if (Status == STATUS_TIMEOUT)
	{
		LogMessage("RemoteCall: TID=%u timed out waiting for APC execution.\n", ThreadId);
		ExFreePoolWithTag(Ctx, 'lcRH');
		return STATUS_TIMEOUT;
	}

	*OutResult = Ctx->Result;

	LogMessage("RemoteCall: TID=%u function %p returned 0x%08X.\n",
		ThreadId, reinterpret_cast<PVOID>(Function), Ctx->Result);

	ExFreePoolWithTag(Ctx, 'lcRH');
	return STATUS_SUCCESS;
}
