
NTSTATUS
EnumerateWindowsKernel(
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;

	if (OutputBuffer == NULL || OutputLength < sizeof(WINDOW_ENUM_OUTPUT))
		return STATUS_BUFFER_TOO_SMALL;

	if (!EnsureWin32kOffsets())
		return STATUS_NOT_FOUND;

	PCHAR OutBuf = (PCHAR)OutputBuffer;
	ULONG OutRemaining = OutputLength;
	ULONG Count = 0;

	((PWINDOW_ENUM_OUTPUT)OutputBuffer)->Count = 0;
	OutBuf += sizeof(ULONG); 
	OutRemaining -= sizeof(ULONG);

	ULONG_PTR GSharedInfo = G_WindowOffsets.GSharedInfo;
	ULONG HandleEntrySize = G_WindowOffsets.HandleEntrySize;
	ULONG HandleEntryCount = G_WindowOffsets.HandleEntryCount;
	ULONG PheadOffset = G_WindowOffsets.HandleEntryPheadOffset;
	ULONG MaxEntries = HandleEntryCount;

	ULONG_PTR aheList = 0;
	__try
	{
		for (ULONG i = 0; i < 8; i++)
		{
			ULONG_PTR Val = *(volatile ULONG_PTR*)(GSharedInfo + i * sizeof(ULONG_PTR));
			ULONG_PTR Next = *(volatile ULONG_PTR*)(GSharedInfo + (i + 1) * sizeof(ULONG_PTR));
			if (Val > 0xFFFF000000000000ULL && Next > Val && (Next - Val) >= 0x1000)
			{
				aheList = Val;
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (aheList == 0)
		return STATUS_UNSUCCESSFUL;

	__try
	{
		for (ULONG i = 0; i < MaxEntries && OutRemaining >= (LONG)(sizeof(WINDOW_ENUM_ENTRY) + 512); i++)
		{
			ULONG_PTR EntryAddr = aheList + (ULONG_PTR)i * HandleEntrySize;
			ULONG_PTR tagWnd = *(volatile ULONG_PTR*)(EntryAddr + PheadOffset);

			if (tagWnd == 0 || tagWnd < 0xFFFF000000000000ULL)
				continue;

			PWINDOW_ENUM_ENTRY Entry = (PWINDOW_ENUM_ENTRY)OutBuf;
			RtlZeroMemory(Entry, sizeof(WINDOW_ENUM_ENTRY));

			Entry->Hwnd = ((ULONG_PTR)i & 0xFFFF) | ((ULONG_PTR)i << 16);

			ULONG off_idProc    = G_WindowOffsets.TagWnd_IdProcess;
			ULONG off_idThread  = G_WindowOffsets.TagWnd_IdThread;
			ULONG off_dwStyle   = G_WindowOffsets.TagWnd_DwStyle;
			ULONG off_dwExStyle = G_WindowOffsets.TagWnd_DwExStyle;
			ULONG off_state     = G_WindowOffsets.TagWnd_State;
			ULONG off_state2    = G_WindowOffsets.TagWnd_State2;
			ULONG off_rcWindow  = G_WindowOffsets.TagWnd_RcWindow;
			ULONG off_rcClient  = G_WindowOffsets.TagWnd_RcClient;
			ULONG off_strName   = G_WindowOffsets.TagWnd_StrName;
			ULONG off_parent    = G_WindowOffsets.TagWnd_SpwndParent;
			ULONG off_owner     = G_WindowOffsets.TagWnd_SpwndOwner;
			ULONG off_child     = G_WindowOffsets.TagWnd_SpwndChild;
			ULONG off_next      = G_WindowOffsets.TagWnd_SpwndNext;
			ULONG off_pcls      = G_WindowOffsets.TagWnd_Pcls;
			ULONG off_wndProc   = G_WindowOffsets.TagWnd_LpfnWndProc;
			ULONG off_pti       = G_WindowOffsets.TagWnd_Pti;
			ULONG off_menu      = G_WindowOffsets.TagWnd_Spmenu;
			ULONG off_cbExtra   = G_WindowOffsets.TagWnd_CbWndExtra;
			ULONG off_pdesk     = G_WindowOffsets.TagWnd_Pdesk;

			if (off_idProc)
				Entry->ProcessId = *(volatile ULONG*)((PUCHAR)tagWnd + off_idProc);
			if (off_idThread)
				Entry->ThreadId = *(volatile ULONG*)((PUCHAR)tagWnd + off_idThread);

			if (off_dwStyle)
				Entry->Style = *(volatile ULONG*)((PUCHAR)tagWnd + off_dwStyle);
			if (off_dwExStyle)
				Entry->ExStyle = *(volatile ULONG*)((PUCHAR)tagWnd + off_dwExStyle);

			if (off_state)
				Entry->State = *(volatile ULONG*)((PUCHAR)tagWnd + off_state);

			if (off_state2)
			{
				ULONG s2 = *(volatile ULONG*)((PUCHAR)tagWnd + off_state2);
				if (off_state)
					Entry->ShowCmd = s2;
			}

			if (off_rcWindow)
			{
				Entry->Left   = *(volatile LONG*)((PUCHAR)tagWnd + off_rcWindow + 0);
				Entry->Top    = *(volatile LONG*)((PUCHAR)tagWnd + off_rcWindow + 4);
				Entry->Right  = *(volatile LONG*)((PUCHAR)tagWnd + off_rcWindow + 8);
				Entry->Bottom = *(volatile LONG*)((PUCHAR)tagWnd + off_rcWindow + 12);
			}

			if (off_rcClient)
			{
				Entry->ClientLeft   = *(volatile LONG*)((PUCHAR)tagWnd + off_rcClient + 0);
				Entry->ClientTop    = *(volatile LONG*)((PUCHAR)tagWnd + off_rcClient + 4);
				Entry->ClientRight  = *(volatile LONG*)((PUCHAR)tagWnd + off_rcClient + 8);
				Entry->ClientBottom = *(volatile LONG*)((PUCHAR)tagWnd + off_rcClient + 12);
			}

			if (off_parent)
				Entry->ParentHwnd = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_parent);
			if (off_owner)
				Entry->OwnerHwnd = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_owner);
			if (off_child)
				Entry->FirstChild = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_child);
			if (off_next)
				Entry->NextSibling = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_next);

			if (off_wndProc)
				Entry->WndProc = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_wndProc);
			if (off_pti)
				Entry->ThreadInfoId = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_pti);
			if (off_menu)
				Entry->MenuHandle = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_menu);
			if (off_cbExtra)
				Entry->CbWndExtra = *(volatile USHORT*)((PUCHAR)tagWnd + off_cbExtra);
			if (off_pdesk)
				Entry->DesktopId = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_pdesk);

			if (off_pcls)
			{
				ULONG_PTR pcls = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_pcls);
				if (pcls > 0xFFFF000000000000ULL)
				{
					Entry->ClassAtom = *(volatile USHORT*)((PUCHAR)pcls + 0x6);
					Entry->WinstaId = *(volatile ULONG_PTR*)((PUCHAR)pcls - 0x60);
				}
			}

			if (off_strName)
			{
				USHORT Length = *(volatile USHORT*)((PUCHAR)tagWnd + off_strName + 0);
				USHORT MaxLength = *(volatile USHORT*)((PUCHAR)tagWnd + off_strName + 2);
				ULONG_PTR Buffer = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + off_strName + 8);

				if (Length > 0 && Buffer > 0xFFFF000000000000ULL && Length <= 510)
				{
					USHORT CopyLen = Length < 510 ? Length : 510;
					RtlCopyMemory((PUCHAR)Entry + sizeof(WINDOW_ENUM_ENTRY),
						(PVOID)Buffer, CopyLen);
					Entry->TitleLength = CopyLen;
				}
			}

			ULONG Flags = 0;
			ULONG CalcState = Entry->State;
			if (CalcState & 0x80000000)  Flags |= WINDOW_FLAG_VISIBLE;
			if (!(CalcState & 0x00000001)) Flags |= WINDOW_FLAG_ENABLED;
			if (CalcState & 0x10000000)  Flags |= WINDOW_FLAG_HUNG;
			if (CalcState & 0x20000000)  Flags |= WINDOW_FLAG_MINIMIZED;
			if (CalcState & 0x40000000)  Flags |= WINDOW_FLAG_MAXIMIZED;

			if (Entry->ExStyle & 0x00000008) Flags |= WINDOW_FLAG_TOPMOST;
			if (Entry->ExStyle & 0x00080000) Flags |= WINDOW_FLAG_LAYERED;
			if (Entry->ExStyle & 0x00000080) Flags |= WINDOW_FLAG_TOOLWINDOW;
			if (Entry->Style & 0x80000000)   Flags |= WINDOW_FLAG_POPUP;
			if (Entry->Style & 0x40000000)   Flags |= WINDOW_FLAG_CHILD;
			if (CalcState & 0x00008000)     Flags |= WINDOW_FLAG_UNICODE;
			if (Entry->ExStyle & 0x00000040) Flags |= WINDOW_FLAG_MDI;
			if (Entry->ExStyle & 0x00040000) Flags |= WINDOW_FLAG_APPWINDOW;

			Entry->Flags = Flags;

			ULONG EntryBytes = (ULONG)(sizeof(WINDOW_ENUM_ENTRY) + ((Entry->TitleLength + 1) & ~1));
			OutBuf += EntryBytes;
			OutRemaining -= EntryBytes;
			Count++;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LogMessage("WindowEnum: exception during handle table walk.\n");
	}

	((PWINDOW_ENUM_OUTPUT)OutputBuffer)->Count = Count;
	*BytesReturned = (ULONG)(OutBuf - (PCHAR)OutputBuffer);

	LogMessage("WindowEnum: returned %u windows (%u bytes).\n", Count, *BytesReturned);
	return STATUS_SUCCESS;
}
