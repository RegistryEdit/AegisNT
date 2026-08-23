
NTSTATUS
RemoveAllRegistryCallbacks(
	VOID
)
{
	if (G_CmCallbackActive && G_CmCallbackCookie.QuadPart != 0)
	{
		CmUnRegisterCallback(G_CmCallbackCookie);
		LogMessage("CmCallback unregistered via API.\n");
	}

	PLIST_ENTRY ListHead = NULL;
	NTSTATUS    Status = FindCmCallbackListHead(&ListHead);
	if (!NT_SUCCESS(Status) || ListHead == NULL)
	{
		LogMessage("RemoveAllRegistryCallbacks: FindCmCallbackListHead failed 0x%08X\n", Status);
		G_CmCallbackActive = FALSE;
		G_CmCallbackCookie.QuadPart = 0;
		return Status;
	}

	PMY_MODULE_INFO ModuleInfo = GetSystemModuleInfo();

	PLIST_ENTRY Entry = ListHead->Flink;
	while (Entry != ListHead)
	{
		PLIST_ENTRY Next;
		PVOID CallbackFunc = NULL;
		__try
		{
			Next = Entry->Flink;
			CallbackFunc = *(PVOID*)((PUCHAR)Entry + 0x28);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (ModuleInfo != NULL && IsAddressInSystemModule(CallbackFunc, ModuleInfo))
		{
			LogMessage("Skipping system Cm callback (func 0x%p).\n", CallbackFunc);
		}
		else
		{
			RemoveEntryList(Entry);
		}

		Entry = Next;
	}

	if (ModuleInfo != NULL)
		ExFreePoolWithTag(ModuleInfo, POOL_TAG);

	G_CmCallbackActive = FALSE;
	G_CmCallbackCookie.QuadPart = 0;

	LogMessage("Non-system Registry callbacks removed.\n");
	return STATUS_SUCCESS;
}
