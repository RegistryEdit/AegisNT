
#define MAX_PROTECTED_WINDOWS 256
static ULONG
GetWindowProtectionFlags(
	_In_ UINT64 Hwnd
)
{
	ULONG Result = 0;
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_WindowListLock, &LockIrql);
	PLIST_ENTRY Current = G_WindowListHead.Flink;
	while (Current != &G_WindowListHead)
	{
		PPROTECTED_WINDOW_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_WINDOW_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->Hwnd == Hwnd)
		{
			Result = Entry->ProtectionFlags;
			break;
		}
	}
	KeReleaseSpinLock(&G_WindowListLock, LockIrql);
	return Result;
}

static BOOLEAN
IsWindowProtected(
	_In_ UINT64 Hwnd
)
{
	return GetWindowProtectionFlags(Hwnd) != 0;
}

static NTSTATUS
AddWindowToProtectionList(
	_In_ UINT64 Hwnd,
	_In_ ULONG ProcessId,
	_In_ ULONG ProtectionFlags
)
{
	KIRQL LockIrql;

	if (G_WindowCount >= MAX_PROTECTED_WINDOWS)
		return STATUS_INSUFFICIENT_RESOURCES;

	PPROTECTED_WINDOW_ENTRY NewEntry = (PPROTECTED_WINDOW_ENTRY)
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROTECTED_WINDOW_ENTRY), POOL_TAG);
	if (NewEntry == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(NewEntry, sizeof(*NewEntry));
	NewEntry->Hwnd = Hwnd;
	NewEntry->ProcessId = ProcessId;
	NewEntry->ProtectionFlags = ProtectionFlags;

	if (G_WindowOffsets.Valid)
	{
		ULONG_PTR tagWnd = 0;
		ULONG_PTR aheList = *(volatile ULONG_PTR*)(G_WindowOffsets.GSharedInfo);
		for (ULONG i = 0; i < 8; i++)
		{
			ULONG_PTR Val = *(volatile ULONG_PTR*)(G_WindowOffsets.GSharedInfo + i * sizeof(ULONG_PTR));
			ULONG_PTR Next = *(volatile ULONG_PTR*)(G_WindowOffsets.GSharedInfo + (i + 1) * sizeof(ULONG_PTR));
			if (Val > 0xFFFF000000000000ULL && Next > Val && (Next - Val) >= 0x1000) { aheList = Val; break; }
		}
		for (ULONG i = 0; i < G_WindowOffsets.HandleEntryCount; i++)
		{
			ULONG_PTR Phead = *(volatile ULONG_PTR*)(aheList + (ULONG_PTR)i * G_WindowOffsets.HandleEntrySize);
			if (Phead > 0xFFFF000000000000ULL)
			{
				ULONG_PTR CandidateHwnd = ((ULONG_PTR)i & 0xFFFF) | ((ULONG_PTR)i << 16);
				if (CandidateHwnd == (ULONG_PTR)Hwnd) { tagWnd = Phead; break; }
			}
		}
		if (tagWnd)
		{
			__try
			{
				NewEntry->StyleSnapshot = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
				NewEntry->ExStyleSnapshot = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle);
				USHORT TLen = *(volatile USHORT*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName);
				ULONG_PTR TBuf = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName + 8);
				if (TLen > 0 && TLen < sizeof(NewEntry->TitleSnapshot) - 2 && TBuf > 0xFFFF000000000000ULL)
					RtlCopyMemory(NewEntry->TitleSnapshot, (PVOID)TBuf, TLen);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}
	}

	KeAcquireSpinLock(&G_WindowListLock, &LockIrql);

	PLIST_ENTRY Current = G_WindowListHead.Flink;
	while (Current != &G_WindowListHead)
	{
		PPROTECTED_WINDOW_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_WINDOW_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->Hwnd == Hwnd)
		{
			KeReleaseSpinLock(&G_WindowListLock, LockIrql);
			ExFreePoolWithTag(NewEntry, POOL_TAG);
			return STATUS_DUPLICATE_NAME;
		}
	}

	InsertHeadList(&G_WindowListHead, &NewEntry->ListEntry);
	G_WindowCount++;
	KeReleaseSpinLock(&G_WindowListLock, LockIrql);

	LogMessage("Window HWND 0x%llX (PID %u) added to protection list.\n", Hwnd, ProcessId);

	PEPROCESS Process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process)))
	{
		ObfDereferenceObject(Process);
		if (!IsProcessProtected(ULongToHandle(ProcessId)))
			AddProcessToProtectionList(ProcessId);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS
RemoveWindowFromProtectionList(
	_In_ UINT64 Hwnd
)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_WindowListLock, &LockIrql);
	BOOLEAN Found = FALSE;
	PLIST_ENTRY Current = G_WindowListHead.Flink;
	while (Current != &G_WindowListHead)
	{
		PPROTECTED_WINDOW_ENTRY Entry = CONTAINING_RECORD(Current, PROTECTED_WINDOW_ENTRY, ListEntry);
		Current = Current->Flink;
		if (Entry->Hwnd == Hwnd)
		{
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, POOL_TAG);
			G_WindowCount--;
			Found = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(&G_WindowListLock, LockIrql);
	if (Found) LogMessage("Window HWND 0x%llX removed from protection list.\n", Hwnd);
	return Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static VOID
ClearWindowProtectionList(VOID)
{
	KIRQL LockIrql;

	KeAcquireSpinLock(&G_WindowListLock, &LockIrql);
	while (!IsListEmpty(&G_WindowListHead))
	{
		PLIST_ENTRY Entry = RemoveHeadList(&G_WindowListHead);
		PPROTECTED_WINDOW_ENTRY WEntry = CONTAINING_RECORD(Entry, PROTECTED_WINDOW_ENTRY, ListEntry);
		ExFreePoolWithTag(WEntry, POOL_TAG);
		G_WindowCount--;
	}
	KeReleaseSpinLock(&G_WindowListLock, LockIrql);
	LogMessage("Window protection list cleared.\n");
}

static VOID
RestoreWindowSnapshot(
	_In_ PPROTECTED_WINDOW_ENTRY Entry
)
{
	if (!G_WindowOffsets.Valid) return;

	ULONG_PTR tagWnd = 0;
	ULONG_PTR aheList = 0;
	__try
	{
		for (ULONG i = 0; i < 8; i++)
		{
			ULONG_PTR Val = *(volatile ULONG_PTR*)(G_WindowOffsets.GSharedInfo + i * sizeof(ULONG_PTR));
			ULONG_PTR Next = *(volatile ULONG_PTR*)(G_WindowOffsets.GSharedInfo + (i + 1) * sizeof(ULONG_PTR));
			if (Val > 0xFFFF000000000000ULL && Next > Val && (Next - Val) >= 0x1000) { aheList = Val; break; }
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return; }

	for (ULONG i = 0; i < G_WindowOffsets.HandleEntryCount; i++)
	{
		ULONG_PTR Phead = *(volatile ULONG_PTR*)(aheList + (ULONG_PTR)i * G_WindowOffsets.HandleEntrySize);
		if (Phead > 0xFFFF000000000000ULL)
		{
			ULONG_PTR CandidateHwnd = ((ULONG_PTR)i & 0xFFFF) | ((ULONG_PTR)i << 16);
			if (CandidateHwnd == (ULONG_PTR)Entry->Hwnd) { tagWnd = Phead; break; }
		}
	}
	if (!tagWnd) return;

	__try
	{
		if (Entry->ProtectionFlags & WINPROT_HIDE)
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) |=
				0x10000000; 

		if (Entry->ProtectionFlags & WINPROT_DISABLE)
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) &=
				~0x08000000u; 

		if (Entry->ProtectionFlags & WINPROT_TOPMOST)
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle) &=
				~0x00000008u;

		if (Entry->ProtectionFlags & WINPROT_TITLE)
		{
			USHORT TLen = *(volatile USHORT*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName);
			ULONG_PTR TBuf = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName + 8);
			if (TLen > 0 && TBuf > 0xFFFF000000000000ULL && Entry->TitleSnapshot[0])
				RtlCopyMemory((PVOID)TBuf, Entry->TitleSnapshot, (TLen < 256 ? TLen : 256));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}
