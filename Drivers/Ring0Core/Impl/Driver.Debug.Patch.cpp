
#ifndef _DBG_RTLPCTOFILEHEADER_DECLARED
#define _DBG_RTLPCTOFILEHEADER_DECLARED
extern "C" {
NTSYSAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);
NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);
}
#endif

static BOOLEAN G_DbgPatched     = FALSE;
static ULONG   G_DbgVarCount    = 0;
static PVOID   G_DbgAddrs[6]    = { 0 };
static UCHAR   G_DbgWanted[6]   = { 0, 0, 0, 0, 1, 1 };
static UCHAR   G_DbgDisable[6]  = { 1, 1, 1, 1, 0, 0 };

#define DBG_NOTPRESENT   0
#define DBG_PITCH        1
#define DBG_BLOCKENABLE  2
#define DBG_BOOTEDNODBG  3
#define DBG_ENABLED      4
#define DBG_LOCALENABLED 5

static const PCHAR G_DbgNames[6] = {
	"KdDebuggerNotPresent",
	"KdPitchDebugger",
	"KdBlockEnable",
	"KdBootedNoDebug",
	"KdDebuggerEnabled",
	"KdLocalDebugEnabled",
};

static PVOID DbgGetW(PCWSTR N) {
	UNICODE_STRING U; RtlInitUnicodeString(&U, N);
	return MmGetSystemRoutineAddress(&U);
}

static NTSTATUS DbgWrite(PVOID A, PUCHAR V, ULONG L) {
	__try { RtlCopyMemory(A, V, L); return STATUS_SUCCESS; }
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return KrnlWriteMemoryMdl(A, V, L);
	}
}

static BOOLEAN DbgDoWrite(ULONG Idx, UCHAR Val) {
	UCHAR V;
	if (G_DbgAddrs[Idx] == NULL) return FALSE;
	if (!NT_SUCCESS(DbgWrite(G_DbgAddrs[Idx], &Val, 1))) return FALSE;
	if (!NT_SUCCESS(KrnlReadMemory(G_DbgAddrs[Idx], &V, 1))) return FALSE;
	return (V == Val);
}

static ULONG DbgScanCode(PVOID Func, PCWSTR FuncName, ULONG MaxLen,
	PVOID* Out, ULONG MaxOut)
{
	PUCHAR C = reinterpret_cast<PUCHAR>(Func);
	ULONG N = 0;
	BOOLEAN LoggedSeed = FALSE;

#define MODRM_IS_RIPREL(b) ((((b) & 0xC7) == 0x05))

	for (ULONG i = 0; i + 6 < MaxLen; )
	{
		ULONG Ln = 0; LONG D = 0;

		if (C[i]==0x80 && MODRM_IS_RIPREL(C[i+1]) && i+7<=MaxLen)
			{ Ln=7; D=*(PLONG)(C+i+2); }
		else if (C[i]==0xF6 && MODRM_IS_RIPREL(C[i+1]) && i+7<=MaxLen)
			{ Ln=7; D=*(PLONG)(C+i+2); }
		else if (C[i]==0xC6 && MODRM_IS_RIPREL(C[i+1]) && i+7<=MaxLen)
			{ Ln=7; D=*(PLONG)(C+i+2); }
		else if (C[i]==0x0F && C[i+1]==0xB6 && MODRM_IS_RIPREL(C[i+2]) && i+7<=MaxLen)
			{ Ln=7; D=*(PLONG)(C+i+3); }
		else if (C[i]==0x0F && C[i+1]==0xBE && MODRM_IS_RIPREL(C[i+2]) && i+7<=MaxLen)
			{ Ln=7; D=*(PLONG)(C+i+3); }
		else if (C[i]==0x38 && MODRM_IS_RIPREL(C[i+1]) && i+6<=MaxLen)
			{ Ln=6; D=*(PLONG)(C+i+2); }
		else if ((C[i]==0x8A||C[i]==0x3A) && MODRM_IS_RIPREL(C[i+1]) && i+6<=MaxLen)
			{ Ln=6; D=*(PLONG)(C+i+2); }
		else if (C[i]==0x84 && MODRM_IS_RIPREL(C[i+1]) && i+6<=MaxLen)
			{ Ln=6; D=*(PLONG)(C+i+2); }
		else if (C[i]==0x88 && MODRM_IS_RIPREL(C[i+1]) && i+6<=MaxLen)
			{ Ln=6; D=*(PLONG)(C+i+2); }
		else { i++; continue; }

		PVOID T = reinterpret_cast<PVOID>(
			reinterpret_cast<ULONG_PTR>(C+i) + Ln + D);

		if (!LoggedSeed && FuncName != NULL)
		{
			LoggedSeed = TRUE;
			LogMessage("DbgScan: first ref in %S = insn@%p -> target %p\n",
				FuncName, reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(C+i)), T);
		}

		BOOLEAN Dup = FALSE;
		for (ULONG k = 0; k < N; k++)
			if (Out[k] == T) { Dup = TRUE; break; }
		if (!Dup && N < MaxOut) Out[N++] = T;
		i += Ln;
	}
#undef MODRM_IS_RIPREL
	return N;
}

static VOID DbgWalkData(ULONG_PTR NtBase, ULONG NtSize,
	PVOID* Pool, ULONG PoolCnt)
{
	if (G_DbgAddrs[DBG_NOTPRESENT] == NULL || PoolCnt == 0) return;

	ULONG_PTR Anchor = reinterpret_cast<ULONG_PTR>(
		G_DbgAddrs[DBG_NOTPRESENT]);
	ULONG_PTR Lo = (Anchor > 0x4000) ? Anchor - 0x4000 : NtBase;
	ULONG_PTR Hi = Anchor + 0x4000;
	if (Hi > NtBase + NtSize) Hi = NtBase + NtSize;

	ULONG Assigned = 0;
	for (ULONG i = 0; i < PoolCnt && Assigned < 6; i++)
	{
		ULONG_PTR A = reinterpret_cast<ULONG_PTR>(Pool[i]);
		if (A < Lo || A >= Hi) continue;

		BOOLEAN Known = FALSE;
		for (ULONG k = 0; k < 6; k++)
			if (G_DbgAddrs[k] == Pool[i]) { Known = TRUE; break; }
		if (Known) continue;

		UCHAR V;
		if (!NT_SUCCESS(KrnlReadMemory(Pool[i], &V, 1))) continue;
		if (V != 0 && V != 1) continue;

		for (ULONG s = 0; s < 6; s++)
		{
			if (G_DbgAddrs[s] == NULL)
			{
				G_DbgAddrs[s] = Pool[i];
				Assigned++;
				LogMessage("DbgWalk: %s = %p (val=%u)\n",
					G_DbgNames[s], Pool[i], V);
				break;
			}
		}
	}
	if (Assigned > 0)
		LogMessage("DbgWalk: filled %u slots.\n", Assigned);
}

static VOID DbgFindAll(VOID)
{
	static const PCWSTR Exports[6] = {
		L"KdDebuggerNotPresent", L"KdPitchDebugger",
		L"KdBlockEnable", L"KdBootedNoDebug",
		L"KdDebuggerEnabled", L"KdLocalDebugEnabled",
	};
	ULONG i;
	ULONG_PTR NtBase = 0;
	ULONG     NtSize = 0;

	{
		ULONG ExpFound = 0;
		for (i = 0; i < 6; i++)
		{
			G_DbgAddrs[i] = DbgGetW(Exports[i]);
			if (G_DbgAddrs[i] != NULL)
			{
				ExpFound++;
				LogMessage("Dbg: [EXP] %s = %p\n", G_DbgNames[i], G_DbgAddrs[i]);
			}
		}
		LogMessage("Dbg: export phase done, %u/6 found.\n", ExpFound);
	}

	if (G_DbgAddrs[DBG_NOTPRESENT] != NULL)
	{
		PVOID Base = NULL;
		RtlPcToFileHeader(G_DbgAddrs[DBG_NOTPRESENT], &Base);
		if (Base != NULL)
		{
			PIMAGE_NT_HEADERS NtHdr = RtlImageNtHeader(Base);
			if (NtHdr != NULL)
			{
				NtBase = reinterpret_cast<ULONG_PTR>(Base);
				NtSize = NtHdr->OptionalHeader.SizeOfImage;
			}
		}
	}
	if (NtBase == 0) {
		LogMessage("Dbg: ntoskrnl NOT FOUND -- code scan SKIPPED!\n");
	} else {
		LogMessage("Dbg: ntoskrnl = %p size 0x%X.\n", (PVOID)NtBase, NtSize);
	}

	if (NtBase != 0)
	{
		PVOID Pool[2048];
		ULONG PoolCnt = 0;

		static const PCWSTR KDExports[] = {
			L"KdEnableDebugger", L"KdDisableDebugger",
			L"KdPollBreakIn", L"KdDebuggerInitialize0",
			L"KdInitSystem", L"KdSystemDebugControl",
			L"KdSendPacket", L"KdReceivePacket",
			L"KdRestore", L"KdSave",
			L"KdRefreshDebuggerNotPresent", L"KdCheckForDebugBreak",
			L"KdpTrap", L"KdpStub",
			L"KdPowerTransition", L"KdDebuggerDataBlock",
		};

		for (i = 0; i < ARRAYSIZE(KDExports); i++)
		{
			PVOID F = DbgGetW(KDExports[i]);
			if (F == NULL) {
				LogMessage("DbgScan: %S -> NOT FOUND.\n", KDExports[i]);
				continue;
			}
			if (KDExports[i][0] == L'K' && KDExports[i][1] == L'd' &&
				KDExports[i][2] == L'D' && KDExports[i][3] == L'e' &&
				KDExports[i][4] == L'b')
			{
				LogMessage("DbgScan: %S -> data export, skipping.\n", KDExports[i]);
				continue;
			}
			ULONG N = DbgScanCode(F, KDExports[i], 0x800,
				Pool + PoolCnt, ARRAYSIZE(Pool) - PoolCnt);
			PoolCnt += N;
			LogMessage("DbgScan: %S -> %u refs.\n", KDExports[i], N);
		}
		LogMessage("Dbg: scan pool = %u refs total.\n", PoolCnt);

		ULONG V = 0;
		for (i = 0; i < PoolCnt; i++) {
			ULONG_PTR A = reinterpret_cast<ULONG_PTR>(Pool[i]);
			if (A >= NtBase && A < NtBase + NtSize)
				Pool[V++] = Pool[i];
		}
		PoolCnt = V;
		LogMessage("Dbg: after nt filter = %u refs.\n", PoolCnt);

		if (G_DbgAddrs[DBG_NOTPRESENT] != NULL && PoolCnt > 0)
		{
			ULONG ProxFilled = 0;
			ULONG_PTR Anchor = reinterpret_cast<ULONG_PTR>(
				G_DbgAddrs[DBG_NOTPRESENT]);
			for (i = 0; i < PoolCnt; i++)
			{
				ULONG_PTR A = reinterpret_cast<ULONG_PTR>(Pool[i]);
				ULONG_PTR D = (A > Anchor) ? (A - Anchor) : (Anchor - A);
				if (D >= 0x2000) continue;

				BOOLEAN Known = FALSE;
				for (ULONG k = 0; k < 6; k++)
					if (G_DbgAddrs[k] == Pool[i]) Known = TRUE;
				if (Known) continue;

				for (ULONG s = 0; s < 6; s++)
				{
					if (G_DbgAddrs[s] == NULL)
					{
						G_DbgAddrs[s] = Pool[i];
						ProxFilled++;
						LogMessage("DbgScan: %s = %p (proximity dist=%I64x)\n",
							G_DbgNames[s], Pool[i], D);
						break;
					}
				}

				BOOLEAN AllFull = TRUE;
				for (ULONG s = 0; s < 6; s++)
					if (G_DbgAddrs[s] == NULL) AllFull = FALSE;
				if (AllFull) break;
			}
			LogMessage("Dbg: proximity filled %u slots.\n", ProxFilled);
		}

		{
			BOOLEAN AllFull = TRUE;
			for (ULONG s = 0; s < 6; s++)
				if (G_DbgAddrs[s] == NULL) AllFull = FALSE;
			if (!AllFull && PoolCnt > 0)
				DbgWalkData(NtBase, NtSize, Pool, PoolCnt);
		}
	}

	G_DbgVarCount = 0;
	for (i = 0; i < 6; i++)
		if (G_DbgAddrs[i] != NULL)
			G_DbgVarCount++;

	for (i = 0; i < 6; i++)
	{
		if (G_DbgAddrs[i] == NULL)
			LogMessage("Dbg: %s NOT FOUND.\n", G_DbgNames[i]);
		else
			LogMessage("Dbg: %s = %p\n", G_DbgNames[i], G_DbgAddrs[i]);
	}

	LogMessage("Dbg: resolved %u / 6.\n", G_DbgVarCount);
}

static NTSTATUS KrnlEnableDebug(VOID)
{
	if (G_DbgPatched) { LogMessage("DbgEnable: already.\n"); return STATUS_SUCCESS; }

	DbgBlockRemove();

	G_DbgPatched = TRUE;
	LogMessage("DbgEnable: hook pass-through mode.\n");
	return STATUS_SUCCESS;
}

static NTSTATUS KrnlDisableDebug(VOID)
{
	if (G_DbgPatched)
		LogMessage("DbgDisable: switching to blocked mode.\n");
	else
		LogMessage("DbgDisable: enabling block (first time).\n");

	NTSTATUS St = DbgBlockInstall();
	if (!NT_SUCCESS(St))
	{
		LogMessage("DbgDisable: hook install failed (0x%08X).\n", St);
		return St;
	}

	G_DbgPatched = FALSE;
	LogMessage("DbgDisable: blocked.\n");
	return STATUS_SUCCESS;
}

static NTSTATUS KrnlQueryDebug(PDEBUG_STATE_OUTPUT Out)
{
	UCHAR T; ULONG i;
	if (Out == NULL) return STATUS_INVALID_PARAMETER;
	RtlZeroMemory(Out, sizeof(*Out));
	if (G_DbgVarCount == 0) DbgFindAll();

	Out->TotalFound = G_DbgVarCount;
	Out->IsPatched  = G_DbgPatched;

	for (i = 0; i < DEBUG_VAR_COUNT; i++)
	{
		PDEBUG_VAR_ENTRY E = &Out->Vars[i];
		for (ULONG j = 0; j < 31 && G_DbgNames[i][j]; j++)
			E->Name[j] = (WCHAR)G_DbgNames[i][j];
		E->Name[31] = 0;
		E->DesiredEnabledValue = G_DbgWanted[i];
		if (G_DbgAddrs[i] == NULL) { E->Found = FALSE; continue; }
		E->Found = TRUE;
		E->Address = (ULONG_PTR)G_DbgAddrs[i];
		if (NT_SUCCESS(KrnlReadMemory(G_DbgAddrs[i], &T, 1)))
			E->CurrentValue = T;
		else E->CurrentValue = 0xFF;
	}

	Out->PatchedSuccessCount = 0;
	for (i = 0; i < DEBUG_VAR_COUNT; i++)
		if (Out->Vars[i].Found &&
			Out->Vars[i].CurrentValue == Out->Vars[i].DesiredEnabledValue)
			Out->PatchedSuccessCount++;

	Out->Status = STATUS_SUCCESS;
	LogMessage("DbgQuery: found=%u ok=%u/%u patched=%u\n",
		Out->TotalFound, Out->PatchedSuccessCount, DEBUG_VAR_COUNT, G_DbgPatched);
	return STATUS_SUCCESS;
}
