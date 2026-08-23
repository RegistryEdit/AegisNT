
NTSTATUS
EnumerateAllCallbacks(
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_  ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;

#define MAX_CALLBACK_ENTRIES 512
	PCALLBACK_ENTRY LocalEntries = (PCALLBACK_ENTRY)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, MAX_CALLBACK_ENTRIES * sizeof(CALLBACK_ENTRY), POOL_TAG);
	if (LocalEntries == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(LocalEntries, MAX_CALLBACK_ENTRIES * sizeof(CALLBACK_ENTRY));
	ULONG LocalCount = 0;

	PMY_MODULE_INFO ModuleInfo = GetSystemModuleInfo();
#define IS_KERNEL_PTR(_ptr) ((ULONG_PTR)(_ptr) >= 0xFFFF000000000000ULL)
#define CALLBACK_BLOCK_MASK (~(ULONG_PTR)0x0F)
#define CALLBACK_FUNCTION_OFFSET 0x08
#define MAX_FILTER_OBJECTS 128
#define ENTRY_EXISTS(_type, _address) \
	([&]() -> BOOLEAN { \
		for (ULONG _i = 0; _i < LocalCount; ++_i) \
		{ \
			if (LocalEntries[_i].Type == (_type) && LocalEntries[_i].Address == (ULONG_PTR)(_address)) \
				return TRUE; \
		} \
		return FALSE; \
	}())
#define TRY_ADD_PS_NOTIFY_SLOT(_type, _slotValue, _source) \
	do { \
		ULONG_PTR _raw = (ULONG_PTR)(_slotValue); \
		if (_raw == 0) \
			break; \
		ULONG_PTR _block = _raw & CALLBACK_BLOCK_MASK; \
		if (!IS_KERNEL_PTR(_block) || !MmIsAddressValid((PVOID)_block)) \
			break; \
		PVOID _function = NULL; \
		__try \
		{ \
			_function = *(PVOID*)((PUCHAR)_block + CALLBACK_FUNCTION_OFFSET); \
		} \
		__except (EXCEPTION_EXECUTE_HANDLER) \
		{ \
			break; \
		} \
		if (_function == NULL || !IS_KERNEL_PTR(_function) || !MmIsAddressValid(_function)) \
			break; \
		if (ENTRY_EXISTS((_type), _function)) \
			break; \
		ADD_CALLBACK_ENTRY((_type), CALLBACK_FLAG_CAN_REMOVE, _function, (_source)); \
	} while (0)
	#define ADD_CALLBACK_ENTRY(_type, _flags, _address, _source) \
	do { \
		if ((_address) == NULL || LocalCount >= MAX_CALLBACK_ENTRIES) \
			break; \
		LocalEntries[LocalCount].Type = (_type); \
		LocalEntries[LocalCount].Flags = (_flags); \
		LocalEntries[LocalCount].Address = (ULONG_PTR)(_address); \
		if (ModuleInfo != NULL) \
		{ \
			WCHAR ModName[64] = { 0 }; \
			GetModuleNameForAddress((_address), ModuleInfo, ModName, 64); \
			RtlStringCchCopyW(LocalEntries[LocalCount].ModuleName, RTL_NUMBER_OF(LocalEntries[LocalCount].ModuleName), ModName); \
		} \
		RtlStringCchCopyW(LocalEntries[LocalCount].SourceName, RTL_NUMBER_OF(LocalEntries[LocalCount].SourceName), (_source)); \
		LocalCount++; \
	} while (0)

	auto FindPsNotifyArray = [](_In_ PCWSTR RoutineName, _In_ ULONG MaxSlots, _Out_ PULONG_PTR ArrayBase) -> BOOLEAN
	{
		*ArrayBase = 0;

		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, RoutineName);
		PUCHAR FuncStart = (PUCHAR)MmGetSystemRoutineAddress(&Name);
		if (FuncStart == NULL)
			return FALSE;

		for (ULONG i = 0; i < 0x400; ++i)
		{
			if ((FuncStart[i] == 0x48 || FuncStart[i] == 0x4C) &&
				FuncStart[i + 1] == 0x8D &&
				(FuncStart[i + 2] & 0xC7) == 0x05)
			{
				LONG Disp = *(PLONG)(FuncStart + i + 3);
				ULONG_PTR Candidate = (ULONG_PTR)(FuncStart + i + 7 + Disp);
				if (!IS_KERNEL_PTR(Candidate))
					continue;

				ULONG Valid = 0;
				__try
				{
					for (ULONG Slot = 0; Slot < MaxSlots; ++Slot)
					{
						ULONG_PTR EntryValue = *(ULONG_PTR*)(Candidate + Slot * sizeof(ULONG_PTR));
						if (EntryValue == 0)
							continue;
						ULONG_PTR Block = EntryValue & CALLBACK_BLOCK_MASK;
						if (!IS_KERNEL_PTR(Block) || !MmIsAddressValid((PVOID)Block))
						{
							Valid = 0;
							break;
						}
						PVOID Function = *(PVOID*)((PUCHAR)Block + CALLBACK_FUNCTION_OFFSET);
						if (Function == NULL || !IS_KERNEL_PTR(Function) || !MmIsAddressValid(Function))
						{
							Valid = 0;
							break;
						}
						Valid++;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					continue;
				}

				if (Valid > 0)
				{
					*ArrayBase = Candidate;
					return TRUE;
				}
			}
		}

		return FALSE;
	};

	auto FindFilterOperationsOffset = []() -> ULONG_PTR
	{
		if (G_FilterHandle == NULL)
			return 0;

		PUCHAR Base = reinterpret_cast<PUCHAR>(G_FilterHandle);
		for (ULONG_PTR Off = 0; Off < 0x400; Off += sizeof(PVOID))
		{
			__try
			{
				if (*(PVOID UNALIGNED*)(Base + Off) == (PVOID)G_FltOperations)
					return Off;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return 0;
			}
		}
		return 0;
	};

	auto FindBugCheckListHead = [](_In_ PCWSTR RoutineName, _In_ ULONG CallbackOffset, _Out_ PLIST_ENTRY* ListHead) -> BOOLEAN
	{
		*ListHead = NULL;

		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, RoutineName);
		PUCHAR FuncStart = (PUCHAR)MmGetSystemRoutineAddress(&Name);
		if (FuncStart == NULL)
			return FALSE;

		for (ULONG i = 0; i < 0x400; ++i)
		{
			if ((FuncStart[i] != 0x48 && FuncStart[i] != 0x4C) ||
				FuncStart[i + 1] != 0x8D ||
				(FuncStart[i + 2] & 0xC7) != 0x05)
				continue;

			LONG Disp = *(PLONG)(FuncStart + i + 3);
			PLIST_ENTRY Candidate = (PLIST_ENTRY)(FuncStart + i + 7 + Disp);

			__try
			{
				if (!IS_KERNEL_PTR(Candidate) || !MmIsAddressValid(Candidate))
					continue;
				if (!IS_KERNEL_PTR(Candidate->Flink) || !IS_KERNEL_PTR(Candidate->Blink))
					continue;
				if (Candidate->Flink == NULL || Candidate->Blink == NULL)
					continue;

				if (Candidate->Flink != Candidate)
				{
					PUCHAR Record = (PUCHAR)Candidate->Flink;
					PVOID Callback = *(PVOID*)(Record + CallbackOffset);
					if (Callback == NULL || !IS_KERNEL_PTR(Callback) || !MmIsAddressValid(Callback))
						continue;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}

			*ListHead = Candidate;
			return TRUE;
		}

		return FALSE;
	};

	auto FindShutdownListHead = [](_Out_ PLIST_ENTRY* ListHead) -> BOOLEAN
	{
		*ListHead = NULL;

		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, L"IoRegisterShutdownNotification");
		PUCHAR FuncStart = (PUCHAR)MmGetSystemRoutineAddress(&Name);
		if (FuncStart == NULL)
			return FALSE;

		for (ULONG i = 0; i < 0x400; ++i)
		{
			if ((FuncStart[i] != 0x48 && FuncStart[i] != 0x4C) ||
				FuncStart[i + 1] != 0x8D ||
				(FuncStart[i + 2] & 0xC7) != 0x05)
				continue;

			LONG Disp = *(PLONG)(FuncStart + i + 3);
			PLIST_ENTRY Candidate = (PLIST_ENTRY)(FuncStart + i + 7 + Disp);

			__try
			{
				if (!IS_KERNEL_PTR(Candidate) || !MmIsAddressValid(Candidate))
					continue;
				if (!IS_KERNEL_PTR(Candidate->Flink) || !IS_KERNEL_PTR(Candidate->Blink))
					continue;
				if (Candidate->Flink == NULL || Candidate->Blink == NULL)
					continue;

				if (Candidate->Flink != Candidate)
				{
					PDEVICE_OBJECT DeviceObject =
						CONTAINING_RECORD(Candidate->Flink, DEVICE_OBJECT, Queue.ListEntry);
					if (!IS_KERNEL_PTR(DeviceObject) || !MmIsAddressValid(DeviceObject))
						continue;
					if (DeviceObject->DriverObject == NULL || !IS_KERNEL_PTR(DeviceObject->DriverObject) ||
						!MmIsAddressValid(DeviceObject->DriverObject))
						continue;
					PDRIVER_DISPATCH ShutdownDispatch = DeviceObject->DriverObject->MajorFunction[IRP_MJ_SHUTDOWN];
					if (ShutdownDispatch == NULL || !IS_KERNEL_PTR(ShutdownDispatch) || !MmIsAddressValid(ShutdownDispatch))
						continue;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}

			*ListHead = Candidate;
			return TRUE;
		}

		return FALSE;
	};

	ULONG ObOffset = 0;
	NTSTATUS Status = FindObCallbackListOffset(&ObOffset);

	if (NT_SUCCESS(Status))
	{
		POBJECT_TYPE ObjectTypes[2];
		ObjectTypes[0] = *PsProcessType;
		ObjectTypes[1] = *PsThreadType;

		for (INT t = 0; t < 2; t++)
		{
			PUCHAR      Base = (PUCHAR)ObjectTypes[t];
			PLIST_ENTRY ListHead = (PLIST_ENTRY)(Base + ObOffset);
			PLIST_ENTRY Entry = ListHead->Flink;

			while (Entry != ListHead && LocalCount < MAX_CALLBACK_ENTRIES)
			{
				PLIST_ENTRY Next;
				PVOID       PreOp = NULL;
				__try
				{
					Next = Entry->Flink;
					PreOp = *(PVOID*)((PUCHAR)Entry + 0x20);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					break;
				}
				ADD_CALLBACK_ENTRY(
					(t == 0) ? CALLBACK_TYPE_OB_PROCESS : CALLBACK_TYPE_OB_THREAD,
					CALLBACK_FLAG_CAN_REMOVE,
					PreOp,
					(t == 0) ? L"PsProcessType" : L"PsThreadType");
				Entry = Next;
			}
		}
	}

	PLIST_ENTRY CmListHead = NULL;
	Status = FindCmCallbackListHead(&CmListHead);

	if (NT_SUCCESS(Status) && CmListHead != NULL)
	{
		PLIST_ENTRY Entry = CmListHead->Flink;

		while (Entry != CmListHead && LocalCount < MAX_CALLBACK_ENTRIES)
		{
			PLIST_ENTRY Next;
			PVOID       CallbackFunc = NULL;
			__try
			{
				Next = Entry->Flink;
				CallbackFunc = *(PVOID*)((PUCHAR)Entry + 0x28);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
			ADD_CALLBACK_ENTRY(
				CALLBACK_TYPE_REGISTRY,
				CALLBACK_FLAG_CAN_REMOVE,
				CallbackFunc,
				L"CmCallbackListHead");
			Entry = Next;
		}
	}

	{
		ULONG_PTR PsProcessArray = 0;
		if (FindPsNotifyArray(L"PsSetCreateProcessNotifyRoutine", 64, &PsProcessArray))
		{
			for (ULONG i = 0; i < 64 && LocalCount < MAX_CALLBACK_ENTRIES; ++i)
				TRY_ADD_PS_NOTIFY_SLOT(CALLBACK_TYPE_PS_PROCESS_NOTIFY, *(ULONG_PTR*)(PsProcessArray + i * sizeof(ULONG_PTR)),
					L"PspProcessNotifyRoutine");
		}

		ULONG_PTR PsThreadArray = 0;
		if (FindPsNotifyArray(L"PsSetCreateThreadNotifyRoutine", 64, &PsThreadArray))
		{
			for (ULONG i = 0; i < 64 && LocalCount < MAX_CALLBACK_ENTRIES; ++i)
				TRY_ADD_PS_NOTIFY_SLOT(CALLBACK_TYPE_PS_THREAD_NOTIFY, *(ULONG_PTR*)(PsThreadArray + i * sizeof(ULONG_PTR)),
					L"PspThreadNotifyRoutine");
		}

		ULONG_PTR PsImageArray = 0;
		if (FindPsNotifyArray(L"PsSetLoadImageNotifyRoutine", 8, &PsImageArray))
		{
			for (ULONG i = 0; i < 8 && LocalCount < MAX_CALLBACK_ENTRIES; ++i)
				TRY_ADD_PS_NOTIFY_SLOT(CALLBACK_TYPE_PS_IMAGE_NOTIFY, *(ULONG_PTR*)(PsImageArray + i * sizeof(ULONG_PTR)),
					L"PspLoadImageNotifyRoutine");
		}
	}

	if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(1))
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_PS_PROCESS_NOTIFY, CALLBACK_FLAG_CAN_REMOVE, MdvProcessNotify, L"AegisCore PsNotify");
	else if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(2))
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_PS_PROCESS_NOTIFY, CALLBACK_FLAG_CAN_REMOVE, MdvLegacyProcessNotify, L"AegisCore PsNotify");

	if (G_PsThreadNotifyHandle)
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_PS_THREAD_NOTIFY, CALLBACK_FLAG_CAN_REMOVE, MdvThreadNotify, L"AegisCore PsNotify");

	if (G_PsImageNotifyHandle)
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_PS_IMAGE_NOTIFY, CALLBACK_FLAG_CAN_REMOVE, MdvImageNotify, L"AegisCore PsNotify");

	if (G_BugCheckCallbackActive)
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_BUGCHECK, CALLBACK_FLAG_CAN_REMOVE, MdvBugCheckCallback, L"AegisCore BugCheck");

	if (G_BugCheckReasonCallbackActive)
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_BUGCHECK_REASON, CALLBACK_FLAG_CAN_REMOVE, MdvBugCheckReasonCallback,
			L"AegisCore BugCheckReason");

	if (G_ShutdownCallbackActive)
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_SHUTDOWN, CALLBACK_FLAG_CAN_REMOVE, DispatchShutdown, L"AegisCore Shutdown");

	{
		PLIST_ENTRY BugCheckListHead = NULL;
		if (FindBugCheckListHead(L"KeRegisterBugCheckCallback",
			FIELD_OFFSET(KBUGCHECK_CALLBACK_RECORD, CallbackRoutine), &BugCheckListHead))
		{
			PLIST_ENTRY Entry = BugCheckListHead->Flink;
			while (Entry != BugCheckListHead && LocalCount < MAX_CALLBACK_ENTRIES)
			{
				PLIST_ENTRY Next;
				PVOID       Callback = NULL;
				__try
				{
					Next = Entry->Flink;
					PKBUGCHECK_CALLBACK_RECORD Record =
						CONTAINING_RECORD(Entry, KBUGCHECK_CALLBACK_RECORD, Entry);
					if (MmIsAddressValid(Record))
						Callback = (PVOID)Record->CallbackRoutine;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					break;
				}
				if (Callback != NULL && IS_KERNEL_PTR(Callback) &&
					!ENTRY_EXISTS(CALLBACK_TYPE_BUGCHECK, Callback))
					ADD_CALLBACK_ENTRY(CALLBACK_TYPE_BUGCHECK, CALLBACK_FLAG_CAN_REMOVE, Callback, L"KeBugCheckCallbackListHead");
				Entry = Next;
			}
		}

		PLIST_ENTRY BugCheckReasonListHead = NULL;
		if (FindBugCheckListHead(L"KeRegisterBugCheckReasonCallback",
			FIELD_OFFSET(KBUGCHECK_REASON_CALLBACK_RECORD, CallbackRoutine), &BugCheckReasonListHead))
		{
			PLIST_ENTRY Entry = BugCheckReasonListHead->Flink;
			while (Entry != BugCheckReasonListHead && LocalCount < MAX_CALLBACK_ENTRIES)
			{
				PLIST_ENTRY Next;
				PVOID       Callback = NULL;
				__try
				{
					Next = Entry->Flink;
					PKBUGCHECK_REASON_CALLBACK_RECORD Record =
						CONTAINING_RECORD(Entry, KBUGCHECK_REASON_CALLBACK_RECORD, Entry);
					if (MmIsAddressValid(Record))
						Callback = (PVOID)Record->CallbackRoutine;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					break;
				}
				if (Callback != NULL && IS_KERNEL_PTR(Callback) &&
					!ENTRY_EXISTS(CALLBACK_TYPE_BUGCHECK_REASON, Callback))
					ADD_CALLBACK_ENTRY(CALLBACK_TYPE_BUGCHECK_REASON, CALLBACK_FLAG_CAN_REMOVE, Callback, L"KeBugCheckReasonListHead");
				Entry = Next;
			}
		}

		PLIST_ENTRY ShutdownListHead = NULL;
		if (FindShutdownListHead(&ShutdownListHead))
		{
			PLIST_ENTRY Entry = ShutdownListHead->Flink;
			while (Entry != ShutdownListHead && LocalCount < MAX_CALLBACK_ENTRIES)
			{
				PLIST_ENTRY Next;
				PVOID       ShutdownDispatch = NULL;
				__try
				{
					Next = Entry->Flink;
					PDEVICE_OBJECT DeviceObject = CONTAINING_RECORD(Entry, DEVICE_OBJECT, Queue.ListEntry);
					if (MmIsAddressValid(DeviceObject) &&
						DeviceObject->DriverObject != NULL &&
						IS_KERNEL_PTR(DeviceObject->DriverObject) &&
						MmIsAddressValid(DeviceObject->DriverObject))
					{
						ShutdownDispatch = (PVOID)DeviceObject->DriverObject->MajorFunction[IRP_MJ_SHUTDOWN];
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					break;
				}
				if (ShutdownDispatch != NULL && IS_KERNEL_PTR(ShutdownDispatch) &&
					!ENTRY_EXISTS(CALLBACK_TYPE_SHUTDOWN, ShutdownDispatch))
					ADD_CALLBACK_ENTRY(CALLBACK_TYPE_SHUTDOWN, CALLBACK_FLAG_CAN_REMOVE, ShutdownDispatch, L"IopNotifyShutdownQueueHead");
				Entry = Next;
			}
		}
	}

	{
		const ULONG_PTR OperationsOffset = FindFilterOperationsOffset();
		if (OperationsOffset != 0)
		{
			PFLT_FILTER Filters[MAX_FILTER_OBJECTS] = {};
			ULONG NumberFiltersReturned = 0;
			NTSTATUS EnumStatus = FltEnumerateFilters(Filters, RTL_NUMBER_OF(Filters), &NumberFiltersReturned);
			if (NT_SUCCESS(EnumStatus) || EnumStatus == STATUS_BUFFER_TOO_SMALL)
			{
				const ULONG FilterCount = min(NumberFiltersReturned, (ULONG)RTL_NUMBER_OF(Filters));
				for (ULONG i = 0; i < FilterCount && LocalCount < MAX_CALLBACK_ENTRIES; ++i)
				{
					PFLT_FILTER Filter = Filters[i];
					if (Filter == NULL || !MmIsAddressValid(Filter))
						continue;

					PFLT_OPERATION_REGISTRATION Operations = NULL;
					__try
					{
						Operations =
							*(PFLT_OPERATION_REGISTRATION UNALIGNED*)((PUCHAR)Filter + OperationsOffset);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						goto NextFilter;
					}
					if (Operations == NULL || !MmIsAddressValid(Operations))
						goto NextFilter;

					WCHAR FilterSource[64] = { 0 };
					swprintf_s(FilterSource, RTL_NUMBER_OF(FilterSource), L"Flt@%p", Filter);

					for (ULONG OpIndex = 0; OpIndex < 64 && LocalCount < MAX_CALLBACK_ENTRIES; ++OpIndex)
					{
						if (!MmIsAddressValid(&Operations[OpIndex]))
							break;

						const FLT_OPERATION_REGISTRATION &Op = Operations[OpIndex];
						if (Op.MajorFunction == IRP_MJ_OPERATION_END)
							break;
						if (Op.PreOperation == NULL || !IS_KERNEL_PTR(Op.PreOperation))
							continue;
						if (ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_CREATE, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_SET_INFORMATION, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_WRITE, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_READ, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_CLEANUP, Op.PreOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_PRE_CLOSE, Op.PreOperation))
							continue;

						switch (Op.MajorFunction)
						{
						case IRP_MJ_CREATE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_CREATE, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_READ:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_READ, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_QUERY_INFORMATION:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_SET_INFORMATION:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_SET_INFORMATION, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_DIRECTORY_CONTROL:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_WRITE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_WRITE, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_CLEANUP:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_CLEANUP, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						case IRP_MJ_CLOSE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_CLOSE, CALLBACK_FLAG_CAN_REMOVE, Op.PreOperation, FilterSource);
							break;
						default:
							break;
						}

						if (Op.PostOperation == NULL || !IS_KERNEL_PTR(Op.PostOperation))
							continue;
						if (ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_CREATE, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_READ, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_SET_INFORMATION, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_WRITE, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_CLEANUP, Op.PostOperation) ||
							ENTRY_EXISTS(CALLBACK_TYPE_FLT_POST_CLOSE, Op.PostOperation))
							continue;

						switch (Op.MajorFunction)
						{
						case IRP_MJ_CREATE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_CREATE, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_READ:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_READ, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_QUERY_INFORMATION:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_SET_INFORMATION:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_SET_INFORMATION, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_DIRECTORY_CONTROL:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_WRITE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_WRITE, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_CLEANUP:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_CLEANUP, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						case IRP_MJ_CLOSE:
							ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_POST_CLOSE, CALLBACK_FLAG_CAN_REMOVE, Op.PostOperation, FilterSource);
							break;
						default:
							break;
						}
					}

				NextFilter:
					FltObjectDereference(Filter);
				}
			}
		}
	}

	if (G_FltFilterActive)
	{
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_CREATE, CALLBACK_FLAG_CAN_REMOVE, PreCreateCallback, L"AegisCore Minifilter");
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_SET_INFORMATION, CALLBACK_FLAG_CAN_REMOVE, PreSetInformationCallback, L"AegisCore Minifilter");
		ADD_CALLBACK_ENTRY(CALLBACK_TYPE_FLT_PRE_WRITE, CALLBACK_FLAG_CAN_REMOVE, PreWriteCallback, L"AegisCore Minifilter");
	}

	if (ModuleInfo != NULL)
		ExFreePoolWithTag(ModuleInfo, POOL_TAG);

	if (OutputLength >= sizeof(ULONG))
	{
		PCALLBACK_ENUM_OUTPUT Out = (PCALLBACK_ENUM_OUTPUT)OutputBuffer;
		Out->Count = LocalCount;

		if (OutputLength >= sizeof(CALLBACK_ENUM_OUTPUT))
		{
			ULONG MaxEntries = (OutputLength - FIELD_OFFSET(CALLBACK_ENUM_OUTPUT, Entries))
				/ sizeof(CALLBACK_ENTRY);
			ULONG CopyCount = (LocalCount < MaxEntries) ? LocalCount : MaxEntries;

			RtlCopyMemory(Out->Entries, LocalEntries, CopyCount * sizeof(CALLBACK_ENTRY));
			*BytesReturned = FIELD_OFFSET(CALLBACK_ENUM_OUTPUT, Entries)
				+ CopyCount * sizeof(CALLBACK_ENTRY);
		}
		else
		{
			*BytesReturned = sizeof(ULONG);
		}
	}

	ExFreePoolWithTag(LocalEntries, POOL_TAG);
	return (*BytesReturned > 0) ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
#undef MAX_CALLBACK_ENTRIES
#undef IS_KERNEL_PTR
#undef CALLBACK_BLOCK_MASK
#undef CALLBACK_FUNCTION_OFFSET
#undef MAX_FILTER_OBJECTS
#undef ENTRY_EXISTS
#undef TRY_ADD_PS_NOTIFY_SLOT
#undef ADD_CALLBACK_ENTRY
}
