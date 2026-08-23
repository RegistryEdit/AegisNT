
NTSTATUS
RemoveCallbackByAddress(
	_In_ ULONG Type,
	_In_ ULONG_PTR Address
)
{
	if (Address == 0)
		return STATUS_INVALID_PARAMETER;

#define IS_KERNEL_PTR(_ptr) ((ULONG_PTR)(_ptr) >= 0xFFFF000000000000ULL)
#define CALLBACK_BLOCK_MASK (~(ULONG_PTR)0x0F)
#define CALLBACK_FUNCTION_OFFSET 0x08

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

	if (Type == CALLBACK_TYPE_OB_PROCESS || Type == CALLBACK_TYPE_OB_THREAD)
	{
		
		ULONG ObOffset = 0;
		NTSTATUS Status = FindObCallbackListOffset(&ObOffset);

		if (NT_SUCCESS(Status))
		{
			POBJECT_TYPE ObjectTypes[2];
			ObjectTypes[0] = *PsProcessType;
			ObjectTypes[1] = *PsThreadType;

			const INT StartIndex = (Type == CALLBACK_TYPE_OB_PROCESS) ? 0 : 1;
			const INT EndIndex = StartIndex + 1;
			for (INT t = StartIndex; t < EndIndex; t++)
			{
				PUCHAR      Base = (PUCHAR)ObjectTypes[t];
				PLIST_ENTRY ListHead = (PLIST_ENTRY)(Base + ObOffset);
				PLIST_ENTRY Entry = ListHead->Flink;

			while (Entry != ListHead)
			{
				if (!MmIsAddressValid(Entry) || !MmIsAddressValid(Entry->Flink))
					break;

				PLIST_ENTRY Next;
				ULONG_PTR   PreOp = 0;
				__try
				{
					Next = Entry->Flink;
					if (!MmIsAddressValid((PUCHAR)Entry + 0x28))
						break;
					PreOp = (ULONG_PTR)*(PVOID*)((PUCHAR)Entry + 0x20);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					break;
				}

				if (PreOp == Address)
				{
					RemoveEntryList(Entry);
					LogMessage("Removed Ob callback at address 0x%p (type %s).\n",
						(PVOID)Address,
						(t == 0) ? "Process" : "Thread");
					return STATUS_SUCCESS;
				}

				Entry = Next;
			}
			}
		}
	}

	if (Type == CALLBACK_TYPE_REGISTRY)
	{
		
		PLIST_ENTRY CmListHead = NULL;
		NTSTATUS Status = FindCmCallbackListHead(&CmListHead);

		if (NT_SUCCESS(Status) && CmListHead != NULL)
		{
			PLIST_ENTRY Entry = CmListHead->Flink;

		while (Entry != CmListHead)
		{
			PLIST_ENTRY Next;
			ULONG_PTR   CallbackFunc = 0;
			__try
			{
				Next = Entry->Flink;
				CallbackFunc = (ULONG_PTR)*(PVOID*)((PUCHAR)Entry + 0x28);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}

			if (CallbackFunc == Address)
			{
				RemoveEntryList(Entry);
				LogMessage("Removed Registry callback at address 0x%p.\n", (PVOID)Address);
				return STATUS_SUCCESS;
			}

			Entry = Next;
		}
		}
	}

	if (Type == CALLBACK_TYPE_PS_PROCESS_NOTIFY)
	{
		if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(1) &&
			Address == (ULONG_PTR)MdvProcessNotify)
		{
			PsSetCreateProcessNotifyRoutineEx(MdvProcessNotify, TRUE);
			G_PsProcessNotifyHandle = NULL;
			return STATUS_SUCCESS;
		}
		if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(2) &&
			Address == (ULONG_PTR)MdvLegacyProcessNotify)
		{
			PsSetCreateProcessNotifyRoutine(MdvLegacyProcessNotify, TRUE);
			G_PsProcessNotifyHandle = NULL;
			return STATUS_SUCCESS;
		}

		ULONG_PTR ArrayBase = 0;
		if (FindPsNotifyArray(L"PsSetCreateProcessNotifyRoutine", 64, &ArrayBase))
		{
		for (ULONG i = 0; i < 64; ++i)
		{
			volatile ULONG_PTR* Slot = (volatile ULONG_PTR*)(ArrayBase + i * sizeof(ULONG_PTR));
			ULONG_PTR EntryValue = *Slot;
			if (EntryValue == 0)
				continue;
			ULONG_PTR Block = EntryValue & CALLBACK_BLOCK_MASK;
			if (!IS_KERNEL_PTR(Block) || !MmIsAddressValid((PVOID)Block))
				continue;
			ULONG_PTR Function = 0;
			__try
			{
				Function = (ULONG_PTR)*(PVOID*)((PUCHAR)Block + CALLBACK_FUNCTION_OFFSET);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
			if (Function == Address)
			{
				InterlockedExchangePointer((PVOID volatile*)Slot, NULL);
				return STATUS_SUCCESS;
			}
		}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_PS_THREAD_NOTIFY)
	{
		if (G_PsThreadNotifyHandle && Address == (ULONG_PTR)MdvThreadNotify)
		{
			PsRemoveCreateThreadNotifyRoutine(MdvThreadNotify);
			G_PsThreadNotifyHandle = NULL;
			return STATUS_SUCCESS;
		}

		ULONG_PTR ArrayBase = 0;
		if (FindPsNotifyArray(L"PsSetCreateThreadNotifyRoutine", 64, &ArrayBase))
		{
		for (ULONG i = 0; i < 64; ++i)
		{
			volatile ULONG_PTR* Slot = (volatile ULONG_PTR*)(ArrayBase + i * sizeof(ULONG_PTR));
			ULONG_PTR EntryValue = *Slot;
			if (EntryValue == 0)
				continue;
			ULONG_PTR Block = EntryValue & CALLBACK_BLOCK_MASK;
			if (!IS_KERNEL_PTR(Block) || !MmIsAddressValid((PVOID)Block))
				continue;
			ULONG_PTR Function = 0;
			__try
			{
				Function = (ULONG_PTR)*(PVOID*)((PUCHAR)Block + CALLBACK_FUNCTION_OFFSET);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
			if (Function == Address)
			{
				InterlockedExchangePointer((PVOID volatile*)Slot, NULL);
				return STATUS_SUCCESS;
			}
		}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_PS_IMAGE_NOTIFY)
	{
		if (G_PsImageNotifyHandle && Address == (ULONG_PTR)MdvImageNotify)
		{
			PsRemoveLoadImageNotifyRoutine(MdvImageNotify);
			G_PsImageNotifyHandle = NULL;
			return STATUS_SUCCESS;
		}

		ULONG_PTR ArrayBase = 0;
		if (FindPsNotifyArray(L"PsSetLoadImageNotifyRoutine", 8, &ArrayBase))
		{
			for (ULONG i = 0; i < 8; ++i)
			{
				volatile ULONG_PTR* Slot = (volatile ULONG_PTR*)(ArrayBase + i * sizeof(ULONG_PTR));
				ULONG_PTR EntryValue = *Slot;
				if (EntryValue == 0)
					continue;
				ULONG_PTR Block = EntryValue & CALLBACK_BLOCK_MASK;
				if (!IS_KERNEL_PTR(Block) || !MmIsAddressValid((PVOID)Block))
					continue;
				ULONG_PTR Function = (ULONG_PTR)*(PVOID*)((PUCHAR)Block + CALLBACK_FUNCTION_OFFSET);
				if (Function == Address)
				{
					InterlockedExchangePointer((PVOID volatile*)Slot, NULL);
					return STATUS_SUCCESS;
				}
			}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_BUGCHECK)
	{
		if (G_BugCheckCallbackActive && Address == (ULONG_PTR)MdvBugCheckCallback)
		{
			KeDeregisterBugCheckCallback(&G_BugCheckCallbackRecord);
			G_BugCheckCallbackActive = FALSE;
			return STATUS_SUCCESS;
		}

		PLIST_ENTRY ListHead = NULL;
		if (FindBugCheckListHead(L"KeRegisterBugCheckCallback",
			FIELD_OFFSET(KBUGCHECK_CALLBACK_RECORD, CallbackRoutine), &ListHead))
		{
		PLIST_ENTRY Entry = ListHead->Flink;
		while (Entry != ListHead)
		{
			PLIST_ENTRY Next;
			PKBUGCHECK_CALLBACK_RECORD Record = NULL;
			BOOLEAN Match = FALSE;
			__try
			{
				Next = Entry->Flink;
				Record = CONTAINING_RECORD(Entry, KBUGCHECK_CALLBACK_RECORD, Entry);
				if (MmIsAddressValid(Record) && (ULONG_PTR)Record->CallbackRoutine == Address)
					Match = TRUE;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
			if (Match)
			{
				RemoveEntryList(Entry);
				return STATUS_SUCCESS;
			}
			Entry = Next;
		}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_BUGCHECK_REASON)
	{
		if (G_BugCheckReasonCallbackActive && Address == (ULONG_PTR)MdvBugCheckReasonCallback)
		{
			KeDeregisterBugCheckReasonCallback(&G_BugCheckReasonCallbackRecord);
			G_BugCheckReasonCallbackActive = FALSE;
			return STATUS_SUCCESS;
		}

		PLIST_ENTRY ListHead = NULL;
		if (FindBugCheckListHead(L"KeRegisterBugCheckReasonCallback",
			FIELD_OFFSET(KBUGCHECK_REASON_CALLBACK_RECORD, CallbackRoutine), &ListHead))
		{
		PLIST_ENTRY Entry = ListHead->Flink;
		while (Entry != ListHead)
		{
			PLIST_ENTRY Next;
			PKBUGCHECK_REASON_CALLBACK_RECORD Record = NULL;
			BOOLEAN Match = FALSE;
			__try
			{
				Next = Entry->Flink;
				Record = CONTAINING_RECORD(Entry, KBUGCHECK_REASON_CALLBACK_RECORD, Entry);
				if (MmIsAddressValid(Record) && (ULONG_PTR)Record->CallbackRoutine == Address)
					Match = TRUE;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
			if (Match)
			{
				RemoveEntryList(Entry);
				return STATUS_SUCCESS;
			}
			Entry = Next;
		}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_SHUTDOWN)
	{
		if (G_ShutdownCallbackActive && Address == (ULONG_PTR)DispatchShutdown)
		{
			IoUnregisterShutdownNotification(G_DeviceObject);
			G_ShutdownCallbackActive = FALSE;
			return STATUS_SUCCESS;
		}

		PLIST_ENTRY ListHead = NULL;
		if (FindShutdownListHead(&ListHead))
		{
		PLIST_ENTRY Entry = ListHead->Flink;
		while (Entry != ListHead)
		{
			PLIST_ENTRY Next;
			ULONG_PTR ShutdownDispatch = 0;
			__try
			{
				Next = Entry->Flink;
				PDEVICE_OBJECT DeviceObject = CONTAINING_RECORD(Entry, DEVICE_OBJECT, Queue.ListEntry);
				if (MmIsAddressValid(DeviceObject) &&
					DeviceObject->DriverObject != NULL &&
					IS_KERNEL_PTR(DeviceObject->DriverObject) &&
					MmIsAddressValid(DeviceObject->DriverObject))
				{
					ShutdownDispatch = (ULONG_PTR)DeviceObject->DriverObject->MajorFunction[IRP_MJ_SHUTDOWN];
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
			if (ShutdownDispatch == Address)
			{
				RemoveEntryList(Entry);
				return STATUS_SUCCESS;
			}
			Entry = Next;
		}
		}
		return STATUS_NOT_FOUND;
	}

	if (Type == CALLBACK_TYPE_FLT_PRE_CREATE ||
		Type == CALLBACK_TYPE_FLT_PRE_SET_INFORMATION ||
		Type == CALLBACK_TYPE_FLT_PRE_WRITE ||
		Type == CALLBACK_TYPE_FLT_PRE_READ ||
		Type == CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION ||
		Type == CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL ||
		Type == CALLBACK_TYPE_FLT_PRE_CLEANUP ||
		Type == CALLBACK_TYPE_FLT_PRE_CLOSE ||
		Type == CALLBACK_TYPE_FLT_POST_CREATE ||
		Type == CALLBACK_TYPE_FLT_POST_READ ||
		Type == CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION ||
		Type == CALLBACK_TYPE_FLT_POST_SET_INFORMATION ||
		Type == CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL ||
		Type == CALLBACK_TYPE_FLT_POST_WRITE ||
		Type == CALLBACK_TYPE_FLT_POST_CLEANUP ||
		Type == CALLBACK_TYPE_FLT_POST_CLOSE)
	{
		const ULONG_PTR OperationsOffset = FindFilterOperationsOffset();
		if (OperationsOffset != 0)
		{
			PFLT_FILTER Filters[128] = {};
			ULONG NumberFiltersReturned = 0;
			NTSTATUS EnumStatus = FltEnumerateFilters(Filters, RTL_NUMBER_OF(Filters), &NumberFiltersReturned);
			if (NT_SUCCESS(EnumStatus) || EnumStatus == STATUS_BUFFER_TOO_SMALL)
			{
				const ULONG FilterCount = min(NumberFiltersReturned, (ULONG)RTL_NUMBER_OF(Filters));
				for (ULONG i = 0; i < FilterCount; ++i)
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

				for (ULONG OpIndex = 0; OpIndex < 64; ++OpIndex)
				{
					if (!MmIsAddressValid(&Operations[OpIndex]))
						break;

					PFLT_OPERATION_REGISTRATION Op = &Operations[OpIndex];
					ULONG MajorFunc;
					__try
					{
						MajorFunc = Op->MajorFunction;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						break;
					}
					if (MajorFunc == IRP_MJ_OPERATION_END)
						break;

					if ((Type == CALLBACK_TYPE_FLT_PRE_CREATE ||
						Type == CALLBACK_TYPE_FLT_PRE_READ ||
						Type == CALLBACK_TYPE_FLT_PRE_QUERY_INFORMATION ||
						Type == CALLBACK_TYPE_FLT_PRE_SET_INFORMATION ||
						Type == CALLBACK_TYPE_FLT_PRE_DIRECTORY_CONTROL ||
						Type == CALLBACK_TYPE_FLT_PRE_WRITE ||
						Type == CALLBACK_TYPE_FLT_PRE_CLEANUP ||
						Type == CALLBACK_TYPE_FLT_PRE_CLOSE) &&
						(ULONG_PTR)Op->PreOperation == Address)
					{
						Op->PreOperation = NULL;
						return STATUS_SUCCESS;
					}

					if ((Type == CALLBACK_TYPE_FLT_POST_CREATE ||
						Type == CALLBACK_TYPE_FLT_POST_READ ||
						Type == CALLBACK_TYPE_FLT_POST_QUERY_INFORMATION ||
						Type == CALLBACK_TYPE_FLT_POST_SET_INFORMATION ||
						Type == CALLBACK_TYPE_FLT_POST_DIRECTORY_CONTROL ||
						Type == CALLBACK_TYPE_FLT_POST_WRITE ||
						Type == CALLBACK_TYPE_FLT_POST_CLEANUP ||
						Type == CALLBACK_TYPE_FLT_POST_CLOSE) &&
						(ULONG_PTR)Op->PostOperation == Address)
					{
						Op->PostOperation = NULL;
						return STATUS_SUCCESS;
					}
				}

				NextFilter:
					FltObjectDereference(Filter);
				}
			}
		}
		return STATUS_NOT_FOUND;
	}

	LogMessage("RemoveCallbackByAddress: type %lu address 0x%p not found in any callback list.\n",
		Type, (PVOID)Address);
	return STATUS_NOT_FOUND;
#undef IS_KERNEL_PTR
#undef CALLBACK_BLOCK_MASK
#undef CALLBACK_FUNCTION_OFFSET
}

static NTSTATUS
HashImageFileSha256(
	_In_ PCUNICODE_STRING ImagePath,
	_Out_writes_(32) PUCHAR Digest
)
{
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK OpenIoStatus = { 0 };
	InitializeObjectAttributes(
		&ObjectAttributes,
		(PUNICODE_STRING)ImagePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	NTSTATUS Status = ZwCreateFile(
		&FileHandle,
		FILE_READ_DATA | SYNCHRONIZE,
		&ObjectAttributes,
		&OpenIoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("Auth hash: ZwCreateFile(%wZ) failed 0x%08X.\n", ImagePath, Status);
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	BCRYPT_ALG_HANDLE Algorithm = NULL;
	BCRYPT_HASH_HANDLE Hash = NULL;
	PUCHAR Buffer = NULL;
	PUCHAR HashObject = NULL;
	ULONG HashObjectSize = 0;
	ULONG ResultSize = 0;

	Status = BCryptOpenAlgorithmProvider(
		&Algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("Auth hash: BCryptOpenAlgorithmProvider failed 0x%08X.\n", Status);
		Status = STATUS_NOT_SUPPORTED;
		goto Cleanup;
	}

	Status = BCryptGetProperty(
		Algorithm,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&HashObjectSize,
		sizeof(HashObjectSize),
		&ResultSize,
		0);
	if (!NT_SUCCESS(Status) || HashObjectSize == 0)
	{
		LogMessage("Auth hash: BCryptGetProperty failed 0x%08X (size %u).\n",
			Status, HashObjectSize);
		Status = STATUS_INVALID_DEVICE_STATE;
		goto Cleanup;
	}

	HashObject = (PUCHAR)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, HashObjectSize, POOL_TAG);
	if (HashObject == NULL)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	Status = BCryptCreateHash(
		Algorithm, &Hash, HashObject, HashObjectSize, NULL, 0, 0);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("Auth hash: BCryptCreateHash failed 0x%08X.\n", Status);
		Status = STATUS_INVALID_DEVICE_STATE;
		goto Cleanup;
	}

	Buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 64 * 1024, POOL_TAG);
	if (Buffer == NULL)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	LARGE_INTEGER Offset = { 0 };
	for (;;)
	{
		IO_STATUS_BLOCK IoStatus = { 0 };
		Status = ZwReadFile(
			FileHandle, NULL, NULL, NULL, &IoStatus,
			Buffer, 64 * 1024, &Offset, NULL);

		if (Status == STATUS_END_OF_FILE ||
			(NT_SUCCESS(Status) && IoStatus.Information == 0))
		{
			Status = STATUS_SUCCESS;
			break;
		}
		if (!NT_SUCCESS(Status))
		{
			LogMessage("Auth hash: ZwReadFile failed 0x%08X at offset %I64u.\n",
				Status, Offset.QuadPart);
			Status = STATUS_DEVICE_DATA_ERROR;
			goto Cleanup;
		}

		Status = BCryptHashData(Hash, Buffer, (ULONG)IoStatus.Information, 0);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("Auth hash: BCryptHashData failed 0x%08X.\n", Status);
			Status = STATUS_DATA_ERROR;
			goto Cleanup;
		}

		Offset.QuadPart += IoStatus.Information;
	}

	Status = BCryptFinishHash(Hash, Digest, 32, 0);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("Auth hash: BCryptFinishHash failed 0x%08X.\n", Status);
		Status = STATUS_DATA_ERROR;
	}

Cleanup:
	if (Buffer != NULL)
		ExFreePoolWithTag(Buffer, POOL_TAG);
	if (Hash != NULL)
		BCryptDestroyHash(Hash);
	if (HashObject != NULL)
		ExFreePoolWithTag(HashObject, POOL_TAG);
	if (Algorithm != NULL)
		BCryptCloseAlgorithmProvider(Algorithm, 0);
	ZwClose(FileHandle);
	return Status;
}

static NTSTATUS
VerifyRequestorImageSignature(
	_In_ PIRP Irp
)
{
	PAGED_CODE();

	UNICODE_STRING RoutineName;
	RtlInitUnicodeString(&RoutineName, L"SeLocateProcessImageName");
	PSE_LOCATE_PROCESS_IMAGE_NAME LocateProcessImageName =
		(PSE_LOCATE_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&RoutineName);

	if (LocateProcessImageName == NULL)
		return STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(Irp);
	PEPROCESS RequestorProcess = PsGetCurrentProcess();
	PUNICODE_STRING ImagePath = NULL;
	NTSTATUS Status = LocateProcessImageName(RequestorProcess, &ImagePath);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("Auth: SeLocateProcessImageName failed 0x%08X.\n", Status);
		return STATUS_NOT_FOUND;
	}
	if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
	{
		if (ImagePath != NULL)
			ExFreePool(ImagePath);
		return STATUS_NOT_FOUND;
	}

	UCHAR ImageDigest[32] = { 0 };
	Status = HashImageFileSha256(ImagePath, ImageDigest);
	ExFreePool(ImagePath);

	if (!NT_SUCCESS(Status))
		return Status;
	if (RtlCompareMemory(ImageDigest, G_AllowedImageSha256,
			sizeof(G_AllowedImageSha256)) != sizeof(G_AllowedImageSha256))
		return STATUS_ACCESS_DENIED;

	return STATUS_SUCCESS;
}
