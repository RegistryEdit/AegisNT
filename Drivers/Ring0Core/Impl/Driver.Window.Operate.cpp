
static VOID
WindowOpApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (Apc && Apc->SystemArgument1)
	{
		ExFreePoolWithTag(Apc->SystemArgument1, POOL_TAG);
		Apc->SystemArgument1 = NULL;
	}
}

static ULONG_PTR
FindUser32ExportInProcess(
	_In_ PEPROCESS Process,
	_In_ PCSTR FunctionName
)
{
	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	ULONG_PTR Result = 0;

	__try
	{
		PROCESS_BASIC_INFORMATION Pbi;
		NTSTATUS Status = ZwQueryInformationProcess(
			ZwCurrentProcess(),
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (!NT_SUCCESS(Status) || Pbi.PebBaseAddress == NULL)
			__leave;

		PVOID LdrPtr = NULL;
		Status = SafeCopyMemory(&LdrPtr, (PUCHAR)Pbi.PebBaseAddress + 0x018, sizeof(PVOID));
		if (!NT_SUCCESS(Status) || LdrPtr == NULL)
			__leave;

		LIST_ENTRY ListHead;
		Status = SafeCopyMemory(&ListHead, (PUCHAR)LdrPtr + 0x010, sizeof(LIST_ENTRY));
		if (!NT_SUCCESS(Status))
			__leave;

		PLIST_ENTRY Current = ListHead.Flink;
		PVOID HeadPtr = (PVOID)((PUCHAR)LdrPtr + 0x010);

		for (ULONG i = 0; i < 64 && Current != HeadPtr; i++)
		{
			PVOID DllBase = NULL;
			UNICODE_STRING ModName;

			if (!NT_SUCCESS(SafeCopyMemory(&DllBase, (PUCHAR)Current + 0x030, sizeof(PVOID))))
				break;
			if (!NT_SUCCESS(SafeCopyMemory(&ModName, (PUCHAR)Current + 0x058, sizeof(UNICODE_STRING))))
				break;

			if (ModName.Buffer != NULL && DllBase != NULL)
			{
				WCHAR Buf[64] = { 0 };
				ULONG CopyLen = ModName.Length;
				if (CopyLen > sizeof(Buf) - sizeof(WCHAR))
					CopyLen = sizeof(Buf) - sizeof(WCHAR);
				if (NT_SUCCESS(SafeCopyMemory(Buf, ModName.Buffer, CopyLen)))
				{
					Buf[CopyLen / sizeof(WCHAR)] = L'\0';
					if (_wcsicmp(Buf, L"user32.dll") == 0)
					{
						ULONG_PTR User32Base = (ULONG_PTR)DllBase;
						PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)User32Base;
						if (Dos->e_magic == IMAGE_DOS_SIGNATURE)
						{
							PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(User32Base + Dos->e_lfanew);
							if (Nt->Signature == IMAGE_NT_SIGNATURE)
							{
								ULONG ExportRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
								if (ExportRva != 0)
								{
									PIMAGE_EXPORT_DIRECTORY ExpDir = (PIMAGE_EXPORT_DIRECTORY)(User32Base + ExportRva);
									PULONG NameTable = (PULONG)(User32Base + ExpDir->AddressOfNames);
									PUSHORT OrdTable = (PUSHORT)(User32Base + ExpDir->AddressOfNameOrdinals);
									PULONG FuncTable = (PULONG)(User32Base + ExpDir->AddressOfFunctions);

									for (ULONG j = 0; j < ExpDir->NumberOfNames; j++)
									{
										PCCH Nm = (PCCH)(User32Base + NameTable[j]);
										if (strcmp(Nm, FunctionName) == 0)
										{
											Result = User32Base + FuncTable[OrdTable[j]];
											__leave;
										}
									}
								}
							}
						}
						break;
					}
				}
			}

			LIST_ENTRY Next;
			if (!NT_SUCCESS(SafeCopyMemory(&Next, Current, sizeof(LIST_ENTRY))))
				break;
			Current = Next.Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Result = 0;
	}

	KeUnstackDetachProcess(&ApcState);
	return Result;
}

static NTSTATUS
CheckWindowProtectionForOperation(
	_In_ UINT64 Hwnd,
	_In_ ULONG Operation
)
{
	ULONG ProtectionFlags = GetWindowProtectionFlags(Hwnd);
	if (ProtectionFlags == 0)
		return STATUS_SUCCESS;

	ULONG RequiredFlag = 0;
	switch (Operation)
	{
	case WINDOW_OP_CLOSE:
		RequiredFlag = WINPROT_CLOSE;
		break;
	case WINDOW_OP_HIDE:
		RequiredFlag = WINPROT_HIDE;
		break;
	case WINDOW_OP_SET_TITLE:
		RequiredFlag = WINPROT_TITLE;
		break;
	case WINDOW_OP_DISABLE:
		RequiredFlag = WINPROT_DISABLE;
		break;
	case WINDOW_OP_SET_POSITION:
		RequiredFlag = WINPROT_MOVE;
		break;
	case WINDOW_OP_SET_SIZE:
		RequiredFlag = WINPROT_RESIZE;
		break;
	case WINDOW_OP_SET_TOPMOST:
	case WINDOW_OP_REMOVE_TOPMOST:
		RequiredFlag = WINPROT_TOPMOST;
		break;
	default:
		break;
	}

	if (RequiredFlag != 0 && (ProtectionFlags & RequiredFlag) != 0)
	{
		LogMessage("WindowOp: denied operation %u on protected HWND 0x%llX (flags=0x%08X).\n",
			Operation, Hwnd, ProtectionFlags);
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS
OperateWindowViaApc(
	_In_ PEPROCESS TargetProcess,
	_In_ UINT64 Hwnd,
	_In_ ULONG Operation,
	_In_opt_ PCWSTR NewTitle
)
{
	const char* FuncName = NULL;
	PVOID Context = NULL;
	PVOID Arg1 = NULL;
	PVOID Arg2 = NULL;
	BOOLEAN NeedRemoteTitle = FALSE;
	PVOID RemoteTitle = NULL;

	switch (Operation)
	{
	case WINDOW_OP_CLOSE:
		FuncName = "DestroyWindow";
		Context = (PVOID)Hwnd;
		break;
	case WINDOW_OP_HIDE:
		FuncName = "ShowWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)0; 
		break;
	case WINDOW_OP_SHOW:
		FuncName = "ShowWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)5; 
		break;
	case WINDOW_OP_MINIMIZE:
		FuncName = "ShowWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)6; 
		break;
	case WINDOW_OP_RESTORE:
		FuncName = "ShowWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)9; 
		break;
	case WINDOW_OP_ENABLE:
		FuncName = "EnableWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)1;
		break;
	case WINDOW_OP_DISABLE:
		FuncName = "EnableWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)0;
		break;
	case WINDOW_OP_FLASH:
		FuncName = "FlashWindow";
		Context = (PVOID)Hwnd;
		Arg1 = (PVOID)(ULONG_PTR)1;
		break;
	case WINDOW_OP_REDRAW:
		FuncName = "InvalidateRect";
		Context = (PVOID)Hwnd;
		Arg1 = NULL;
		Arg2 = (PVOID)(ULONG_PTR)1; 
		break;
	case WINDOW_OP_SET_TITLE:
		if (NewTitle == NULL)
			return STATUS_INVALID_PARAMETER;
		NeedRemoteTitle = TRUE;
		break;
	case WINDOW_OP_SET_TOPMOST:
	case WINDOW_OP_REMOVE_TOPMOST:
	case WINDOW_OP_SET_POSITION:
	case WINDOW_OP_SET_SIZE:
		
		break;
	default:
		return STATUS_NOT_SUPPORTED;
	}

	if (NeedRemoteTitle)
	{
		KAPC_STATE ApcState;
		KeStackAttachProcess(TargetProcess, &ApcState);

		SIZE_T TitleBytes = (wcslen(NewTitle) + 1) * sizeof(WCHAR);
		SIZE_T AllocSize = (TitleBytes + 0xFFF) & ~(SIZE_T)0xFFF;

		NTSTATUS AllocStatus = ZwAllocateVirtualMemory(
			ZwCurrentProcess(), &RemoteTitle, 0, &AllocSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (NT_SUCCESS(AllocStatus))
		{
			__try
			{
				RtlCopyMemory(RemoteTitle, (PVOID)NewTitle, TitleBytes);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				AllocStatus = STATUS_ACCESS_VIOLATION;
			}
		}

		KeUnstackDetachProcess(&ApcState);

		if (!NT_SUCCESS(AllocStatus))
			return AllocStatus;

		FuncName = "SetWindowTextW";
		Context = (PVOID)Hwnd;
		Arg1 = RemoteTitle;
		Arg2 = NULL;
	}

	ULONG_PTR FuncAddr = FindUser32ExportInProcess(TargetProcess, FuncName);
	if (FuncAddr == 0)
	{
		if (RemoteTitle)
		{
			KAPC_STATE ApcState;
			KeStackAttachProcess(TargetProcess, &ApcState);
			SIZE_T FreeSize = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &RemoteTitle, &FreeSize, MEM_RELEASE);
			KeUnstackDetachProcess(&ApcState);
		}
		LogMessage("WindowOp: cannot find %s in user32.\n", FuncName);
		return STATUS_NOT_FOUND;
	}

	PETHREAD TargetThread = NULL;
	QueueApcFindThread(TargetProcess, &TargetThread);
	if (TargetThread == NULL)
	{
		LogMessage("WindowOp: no threads in target process.\n");
		return STATUS_NOT_FOUND;
	}

	PKAPC Apc = (PKAPC)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG);
	if (Apc == NULL)
	{
		ObDereferenceObject(TargetThread);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(
		Apc,
		TargetThread,
		OriginalApcEnvironment,
		WindowOpApcKernelRoutine,
		NULL,
		(PKNORMAL_ROUTINE)FuncAddr,
		UserMode,
		Context);

	Apc->SystemArgument1 = RemoteTitle;

	BOOLEAN Queued = KeInsertQueueApc(Apc, TargetThread, NULL, IO_NO_INCREMENT);
	ObDereferenceObject(TargetThread);

	if (!Queued)
	{
		ExFreePoolWithTag(Apc, POOL_TAG);
		if (RemoteTitle)
			ExFreePoolWithTag(RemoteTitle, POOL_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	LogMessage("WindowOp: APC queued for operation %u.\n", Operation);
	return STATUS_SUCCESS;
}

static NTSTATUS
OperateWindowViaDirect(
	_In_ UINT64 Hwnd,
	_In_ ULONG Operation,
	_In_opt_ PCWSTR NewTitle,
	_In_ LONG NewX,
	_In_ LONG NewY,
	_In_ LONG NewWidth,
	_In_ LONG NewHeight
)
{
	if (!G_WindowOffsets.Valid)
		return STATUS_NOT_FOUND;

	ULONG_PTR aheList = 0;
	__try
	{
		ULONG_PTR GSharedInfo = G_WindowOffsets.GSharedInfo;
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
		return STATUS_NOT_FOUND;

	ULONG_PTR tagWnd = 0;
	ULONG HandleEntrySize = G_WindowOffsets.HandleEntrySize;
	ULONG HandleEntryCount = G_WindowOffsets.HandleEntryCount;

	for (ULONG i = 0; i < HandleEntryCount; i++)
	{
		ULONG_PTR Phead = *(volatile ULONG_PTR*)(aheList + (ULONG_PTR)i * HandleEntrySize);
		if (Phead > 0xFFFF000000000000ULL)
		{
			ULONG_PTR CandidateHwnd = ((ULONG_PTR)i & 0xFFFF) | ((ULONG_PTR)i << 16);
			if (CandidateHwnd == Hwnd)
			{
				tagWnd = Phead;
				break;
			}
		}
	}

	if (tagWnd == 0)
		return STATUS_NOT_FOUND;

	__try
	{
		switch (Operation)
		{
		case WINDOW_OP_HIDE:
		{
			ULONG style = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
			style &= ~0x10000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) = style;
			break;
		}
		case WINDOW_OP_SHOW:
		{
			ULONG style = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
			style |= 0x10000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) = style;
			break;
		}
		case WINDOW_OP_SET_TITLE:
		{
			if (NewTitle != NULL && G_WindowOffsets.TagWnd_StrName)
			{
				USHORT Len = (USHORT)(wcslen(NewTitle) * sizeof(WCHAR));
				*(volatile USHORT*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName) = Len;
				*(volatile USHORT*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName + 2) = Len + 2;

				ULONG_PTR BufAddr = *(volatile ULONG_PTR*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_StrName + 8);
				if (BufAddr > 0xFFFF000000000000ULL && Len <= 510)
					RtlCopyMemory((PVOID)BufAddr, NewTitle, Len);
			}
			break;
		}
		case WINDOW_OP_MINIMIZE:
		{
			ULONG state = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_State);
			state |= 0x20000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_State) = state;
			break;
		}
		case WINDOW_OP_RESTORE:
		{
			ULONG state = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_State);
			state &= ~0x60000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_State) = state;
			break;
		}
		case WINDOW_OP_ENABLE:
		{
			ULONG style = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
			style &= ~0x08000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) = style;
			break;
		}
		case WINDOW_OP_DISABLE:
		{
			ULONG style = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
			style |= 0x08000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) = style;
			break;
		}
		case WINDOW_OP_SET_POSITION:
		{
			if (G_WindowOffsets.TagWnd_RcWindow)
			{
				LONG w = *(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 8) -
					*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 0);
				LONG h = *(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 12) -
					*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 4);
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 0) = NewX;
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 4) = NewY;
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 8) = NewX + w;
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 12) = NewY + h;
			}
			break;
		}
		case WINDOW_OP_SET_SIZE:
		{
			if (G_WindowOffsets.TagWnd_RcWindow)
			{
				LONG x = *(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 0);
				LONG y = *(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 4);
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 8) = x + (NewWidth > 0 ? NewWidth : 100);
				*(volatile LONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_RcWindow + 12) = y + (NewHeight > 0 ? NewHeight : 100);
			}
			break;
		}
		case WINDOW_OP_SET_TOPMOST:
		{
			ULONG exStyle = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle);
			exStyle |= 0x00000008;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle) = exStyle;
			break;
		}
		case WINDOW_OP_REMOVE_TOPMOST:
		{
			ULONG exStyle = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle);
			exStyle &= ~0x00000008;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwExStyle) = exStyle;
			break;
		}
		case WINDOW_OP_CLOSE:
		{
			ULONG style = *(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle);
			style &= ~0x10000000;
			style |= 0x08000000;
			*(volatile ULONG*)((PUCHAR)tagWnd + G_WindowOffsets.TagWnd_DwStyle) = style;
			break;
		}
		default:
			return STATUS_NOT_SUPPORTED;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	LogMessage("WindowOp: direct modification done for operation %u.\n", Operation);
	return STATUS_SUCCESS;
}

NTSTATUS
WindowOperation(
	_In_ PWINDOW_OPERATION_INPUT Input
)
{
	if (Input == NULL || Input->Operation >= WINDOW_OP_MAX)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS ProtectionStatus = CheckWindowProtectionForOperation(
		Input->Hwnd, Input->Operation);
	if (!NT_SUCCESS(ProtectionStatus))
		return ProtectionStatus;

	PEPROCESS TargetProcess = NULL;
	if (Input->ProcessId != 0)
	{
		NTSTATUS Status = PsLookupProcessByProcessId(
			ULongToHandle(Input->ProcessId), &TargetProcess);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("WindowOp: PID %u not found (0x%08X).\n", Input->ProcessId, Status);
			return Status;
		}
	}

	NTSTATUS Status = STATUS_NOT_SUPPORTED;
	BOOLEAN UseDirect = (Input->Flags & WINDOW_FLAG_DIRECT) != 0;

	if (UseDirect)
	{
		Status = OperateWindowViaDirect(
			Input->Hwnd, Input->Operation,
			Input->NewTitle[0] ? Input->NewTitle : NULL,
			Input->NewX, Input->NewY, Input->NewWidth, Input->NewHeight);

		if (!NT_SUCCESS(Status) && TargetProcess != NULL)
		{
			LogMessage("WindowOp: direct failed (0x%08X), falling back to APC.\n", Status);
			Status = OperateWindowViaApc(
				TargetProcess, Input->Hwnd, Input->Operation,
				Input->NewTitle[0] ? Input->NewTitle : NULL);
		}
	}
	else
	{
		if (TargetProcess != NULL)
		{
			Status = OperateWindowViaApc(
				TargetProcess, Input->Hwnd, Input->Operation,
				Input->NewTitle[0] ? Input->NewTitle : NULL);

			if (!NT_SUCCESS(Status))
			{
				LogMessage("WindowOp: APC failed (0x%08X), falling back to direct.\n", Status);
				Status = OperateWindowViaDirect(
					Input->Hwnd, Input->Operation,
					Input->NewTitle[0] ? Input->NewTitle : NULL,
					Input->NewX, Input->NewY, Input->NewWidth, Input->NewHeight);
			}
		}
		else
		{
			Status = OperateWindowViaDirect(
				Input->Hwnd, Input->Operation,
				Input->NewTitle[0] ? Input->NewTitle : NULL,
				Input->NewX, Input->NewY, Input->NewWidth, Input->NewHeight);
		}
	}

	if (TargetProcess != NULL)
		ObfDereferenceObject(TargetProcess);

	return Status;
}
