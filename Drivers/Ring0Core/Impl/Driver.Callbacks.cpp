
OB_PREOP_CALLBACK_STATUS
ProcessPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	StripDangerousProcessAccess(OperationInformation);
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS
ThreadPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	StripDangerousThreadAccess(OperationInformation);
	return OB_PREOP_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_opt_result_maybenull_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (G_FileCount == 0)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	NTSTATUS Status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&NameInfo);
	if (!NT_SUCCESS(Status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	BOOLEAN Protected = IsFilePathProtected(&NameInfo->Name);
	FltReleaseFileNameInformation(NameInfo);

	if (!Protected)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	ACCESS_MASK DesiredAccess =
		Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

	ACCESS_MASK StrippedAccess = DesiredAccess & ~(
		FILE_WRITE_DATA |
		FILE_APPEND_DATA |
		DELETE |
		FILE_WRITE_ATTRIBUTES |
		FILE_WRITE_EA
		);

	if (StrippedAccess == 0 || DesiredAccess == FILE_READ_DATA || DesiredAccess == SYNCHRONIZE)
		StrippedAccess = FILE_READ_DATA;

	if (StrippedAccess != DesiredAccess)
		Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess = StrippedAccess;

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PreSetInformationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_opt_result_maybenull_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (G_FileCount == 0)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	NTSTATUS Status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&NameInfo);
	if (!NT_SUCCESS(Status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	BOOLEAN Protected = IsFilePathProtected(&NameInfo->Name);
	FltReleaseFileNameInformation(NameInfo);

	if (!Protected)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
	{
	case FileDispositionInformation:
	case FileDispositionInformationEx:
	case FileRenameInformation:
	case FileRenameInformationEx:
	case FileLinkInformation:
	case FileLinkInformationEx:
	case FileEndOfFileInformation:
	case FileAllocationInformation:
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PreWriteCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_opt_result_maybenull_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (G_FileCount == 0)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	NTSTATUS Status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&NameInfo);
	if (!NT_SUCCESS(Status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	BOOLEAN Protected = IsFilePathProtected(&NameInfo->Name);
	FltReleaseFileNameInformation(NameInfo);

	if (!Protected)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	Data->IoStatus.Information = 0;
	return FLT_PREOP_COMPLETE;
}

NTSTATUS
RegistryCallbackRoutine(
	_In_ PVOID CallbackContext,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);

	if (G_RegistryCount == 0)
		return STATUS_SUCCESS;

	REG_NOTIFY_CLASS NotifyClass = static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(Argument1));

	switch (NotifyClass)
	{
	case RegNtPreDeleteKey:
	{
		PREG_DELETE_KEY_INFORMATION Info =
			static_cast<PREG_DELETE_KEY_INFORMATION>(Argument2);
		if (IsRegistryObjectProtected(Info->Object))
			return STATUS_ACCESS_DENIED;
		break;
	}
	case RegNtPreDeleteValueKey:
	{
		PREG_DELETE_VALUE_KEY_INFORMATION Info =
			static_cast<PREG_DELETE_VALUE_KEY_INFORMATION>(Argument2);
		if (IsRegistryObjectProtected(Info->Object))
			return STATUS_ACCESS_DENIED;
		break;
	}
	case RegNtPreSetValueKey:
	{
		PREG_SET_VALUE_KEY_INFORMATION Info =
			static_cast<PREG_SET_VALUE_KEY_INFORMATION>(Argument2);
		if (IsRegistryObjectProtected(Info->Object))
			return STATUS_ACCESS_DENIED;
		break;
	}
	case RegNtPreCreateKeyEx:
	case RegNtPreCreateKey:
	{
		PREG_CREATE_KEY_INFORMATION Info =
			static_cast<PREG_CREATE_KEY_INFORMATION>(Argument2);
		if (Info->CompleteName != NULL && IsRegistryPathProtected(Info->CompleteName))
			return STATUS_ACCESS_DENIED;
		break;
	}
	case RegNtPreRenameKey:
	{
		PREG_RENAME_KEY_INFORMATION Info =
			static_cast<PREG_RENAME_KEY_INFORMATION>(Argument2);
		if (IsRegistryObjectProtected(Info->Object))
			return STATUS_ACCESS_DENIED;
		break;
	}
	case RegNtPreOpenKeyEx:
	{
		PREG_OPEN_KEY_INFORMATION_V2 Info =
			static_cast<PREG_OPEN_KEY_INFORMATION_V2>(Argument2);
		if (Info->CompleteName != NULL &&
			Info->CompleteName->Buffer != NULL &&
			Info->CompleteName->Length >= sizeof(WCHAR))
		{
			WCHAR first = Info->CompleteName->Buffer[0];
			if ((first >= L'A' && first <= L'Z') || first == L'\\')
			{
				if (IsRegistryPathProtected(Info->CompleteName))
					return STATUS_ACCESS_DENIED;
			}
		}
		break;
	}
	default:
		break;
	}

	return STATUS_SUCCESS;
}

static VOID
CreateFltRegistryConfig(
	_In_ PUNICODE_STRING RegistryPath
)
{
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE            ServiceKey = NULL;
	HANDLE            InstancesKey = NULL;
	HANDLE            InstanceKey = NULL;
	NTSTATUS          Status;
	UNICODE_STRING    KeyName;
	UNICODE_STRING    ValueName;
	UNICODE_STRING    ValueData;
	ULONG             Flags = 0;

	InitializeObjectAttributes(&ObjAttr, RegistryPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwOpenKey(&ServiceKey, KEY_CREATE_SUB_KEY, &ObjAttr);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("FltCfg: ZwOpenKey(Service) failed: 0x%08X\n", Status);
		return;
	}

	RtlInitUnicodeString(&KeyName, L"Instances");
	InitializeObjectAttributes(&ObjAttr, &KeyName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, ServiceKey, NULL);

	Status = ZwCreateKey(&InstancesKey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
		&ObjAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	ZwClose(ServiceKey);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("FltCfg: ZwCreateKey(Instances) failed: 0x%08X\n", Status);
		return;
	}

	RtlInitUnicodeString(&ValueName, L"DefaultInstance");
	RtlInitUnicodeString(&ValueData, L"Ring0CoreInstance");
	ZwSetValueKey(InstancesKey, &ValueName, 0, REG_SZ,
		ValueData.Buffer, ValueData.Length + sizeof(WCHAR));

	RtlInitUnicodeString(&KeyName, L"Ring0CoreInstance");
	InitializeObjectAttributes(&ObjAttr, &KeyName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, InstancesKey, NULL);

	Status = ZwCreateKey(&InstanceKey, KEY_SET_VALUE,
		&ObjAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	ZwClose(InstancesKey);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("FltCfg: ZwCreateKey(Instance) failed: 0x%08X\n", Status);
		return;
	}

	RtlInitUnicodeString(&ValueName, L"Altitude");
	RtlInitUnicodeString(&ValueData, L"360000");
	ZwSetValueKey(InstanceKey, &ValueName, 0, REG_SZ,
		ValueData.Buffer, ValueData.Length + sizeof(WCHAR));

	RtlInitUnicodeString(&ValueName, L"Flags");
	ZwSetValueKey(InstanceKey, &ValueName, 0, REG_DWORD,
		&Flags, sizeof(Flags));

	ZwClose(InstanceKey);
	LogMessage("FltCfg: registry configuration complete.\n");
}

static FLT_OPERATION_REGISTRATION G_FltOperations[] = {
	{ IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
	{ IRP_MJ_SET_INFORMATION, 0, PreSetInformationCallback, NULL },
	{ IRP_MJ_WRITE, 0, PreWriteCallback, NULL },
	{ IRP_MJ_OPERATION_END }
};

static VOID NTAPI
MdvProcessNotify(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);
}

static VOID NTAPI
MdvLegacyProcessNotify(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Create);
}

static VOID NTAPI
MdvThreadNotify(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);
}

static VOID NTAPI
MdvImageNotify(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
)
{
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);
}

static VOID NTAPI
MdvBugCheckCallback(
	PVOID Buffer,
	ULONG Length
)
{
	UNREFERENCED_PARAMETER(Buffer);
	UNREFERENCED_PARAMETER(Length);
}

static VOID NTAPI
MdvBugCheckReasonCallback(
	KBUGCHECK_CALLBACK_REASON Reason,
	PKBUGCHECK_REASON_CALLBACK_RECORD Record,
	PVOID ReasonSpecificData,
	ULONG ReasonSpecificDataLength
)
{
	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificData);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
}

static NTSTATUS
RegisterAllCallbacks(VOID)
{
	NTSTATUS Status;

	UNICODE_STRING CmAltitude;
	RtlInitUnicodeString(&CmAltitude, L"999000");

	Status = CmRegisterCallbackEx(
		RegistryCallbackRoutine,
		&CmAltitude,
		(PVOID)G_DeviceObject->DriverObject,
		NULL,
		&G_CmCallbackCookie,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("CmRegisterCallbackEx failed: 0x%08X "
			"(Registry protection unavailable)\n", Status);
	}
	else
	{
		G_CmCallbackActive = TRUE;
		LogMessage("CmCallback registered (altitude 999000).\n");
	}

	OB_OPERATION_REGISTRATION ObOperations[2] = { 0 };

	ObOperations[0].ObjectType = PsProcessType;
	ObOperations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperations[0].PreOperation = ProcessPreOperationCallback;
	ObOperations[0].PostOperation = NULL;

	ObOperations[1].ObjectType = PsThreadType;
	ObOperations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperations[1].PreOperation = ThreadPreOperationCallback;
	ObOperations[1].PostOperation = NULL;

	OB_CALLBACK_REGISTRATION ObRegistration = { 0 };
	ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	ObRegistration.OperationRegistrationCount = 2;
	ObRegistration.OperationRegistration = ObOperations;
	RtlInitUnicodeString(&ObRegistration.Altitude, L"999000");

	Status = ObRegisterCallbacks(&ObRegistration, &G_ObCallbackHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("ObRegisterCallbacks failed: 0x%08X (Process/Thread protection unavailable)\n", Status);
	}
	else
	{
		G_ObCallbacksActive = TRUE;
		LogMessage("ObCallbacks registered (Process + Thread).\n");
	}

	Status = PsSetCreateProcessNotifyRoutineEx(MdvProcessNotify, FALSE);
	if (NT_SUCCESS(Status))
	{
		G_PsProcessNotifyHandle = reinterpret_cast<PVOID>(1);
		LogMessage("Ps process notify registered (Ex).\n");
	}
	else
	{
		LogMessage("Ps process notify Ex failed: 0x%08X, trying legacy.\n", Status);
		Status = PsSetCreateProcessNotifyRoutine(MdvLegacyProcessNotify, FALSE);
		if (NT_SUCCESS(Status))
		{
			G_PsProcessNotifyHandle = reinterpret_cast<PVOID>(2);
			LogMessage("Ps process notify registered (legacy).\n");
		}
		else
		{
			LogMessage("Ps process notify failed: 0x%08X.\n", Status);
		}
	}

	Status = PsSetCreateThreadNotifyRoutine(MdvThreadNotify);
	if (NT_SUCCESS(Status))
	{
		G_PsThreadNotifyHandle = reinterpret_cast<PVOID>(1);
		LogMessage("Ps thread notify registered.\n");
	}
	else
	{
		LogMessage("Ps thread notify failed: 0x%08X.\n", Status);
	}

	Status = PsSetLoadImageNotifyRoutine(MdvImageNotify);
	if (NT_SUCCESS(Status))
	{
		G_PsImageNotifyHandle = reinterpret_cast<PVOID>(1);
		LogMessage("Ps image notify registered.\n");
	}
	else
	{
		LogMessage("Ps image notify failed: 0x%08X.\n", Status);
	}

	KeInitializeCallbackRecord(&G_BugCheckCallbackRecord);
	if (KeRegisterBugCheckCallback(
		&G_BugCheckCallbackRecord,
		MdvBugCheckCallback,
		&G_BugCheckCallbackBuffer,
		sizeof(G_BugCheckCallbackBuffer),
		(const PUCHAR)"AegisCoreBugCheck"))
	{
		G_BugCheckCallbackActive = TRUE;
		LogMessage("Bugcheck callback registered.\n");
	}
	else
	{
		LogMessage("Bugcheck callback registration failed.\n");
	}

	if (KeRegisterBugCheckReasonCallback(
		&G_BugCheckReasonCallbackRecord,
		MdvBugCheckReasonCallback,
		KbCallbackSecondaryDumpData,
		(PUCHAR)"AegisCoreBugReason"))
	{
		G_BugCheckReasonCallbackActive = TRUE;
		LogMessage("Bugcheck reason callback registered.\n");
	}
	else
	{
		LogMessage("Bugcheck reason callback registration failed.\n");
	}

	Status = IoRegisterShutdownNotification(G_DeviceObject);
	if (NT_SUCCESS(Status))
	{
		G_ShutdownCallbackActive = TRUE;
		LogMessage("Shutdown notification registered.\n");
	}
	else
	{
		LogMessage("Shutdown notification failed: 0x%08X.\n", Status);
	}

	return STATUS_SUCCESS;
}

static VOID
UnregisterAllCallbacks(VOID)
{
	if (G_ShutdownCallbackActive)
	{
		IoUnregisterShutdownNotification(G_DeviceObject);
		G_ShutdownCallbackActive = FALSE;
		LogMessage("Shutdown notification unregistered.\n");
	}

	if (G_BugCheckReasonCallbackActive)
	{
		KeDeregisterBugCheckReasonCallback(&G_BugCheckReasonCallbackRecord);
		G_BugCheckReasonCallbackActive = FALSE;
		LogMessage("Bugcheck reason callback unregistered.\n");
	}

	if (G_BugCheckCallbackActive)
	{
		KeDeregisterBugCheckCallback(&G_BugCheckCallbackRecord);
		G_BugCheckCallbackActive = FALSE;
		LogMessage("Bugcheck callback unregistered.\n");
	}

	if (G_PsImageNotifyHandle)
	{
		PsRemoveLoadImageNotifyRoutine(MdvImageNotify);
		G_PsImageNotifyHandle = NULL;
		LogMessage("Ps image notify unregistered.\n");
	}

	if (G_PsThreadNotifyHandle)
	{
		PsRemoveCreateThreadNotifyRoutine(MdvThreadNotify);
		G_PsThreadNotifyHandle = NULL;
		LogMessage("Ps thread notify unregistered.\n");
	}

	if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(1))
	{
		PsSetCreateProcessNotifyRoutineEx(MdvProcessNotify, TRUE);
		G_PsProcessNotifyHandle = NULL;
		LogMessage("Ps process notify (Ex) unregistered.\n");
	}
	else if (G_PsProcessNotifyHandle == reinterpret_cast<PVOID>(2))
	{
		PsSetCreateProcessNotifyRoutine(MdvLegacyProcessNotify, TRUE);
		G_PsProcessNotifyHandle = NULL;
		LogMessage("Ps process notify (legacy) unregistered.\n");
	}

	if (G_CmCallbackActive && G_CmCallbackCookie.QuadPart != 0)
	{
		CmUnRegisterCallback(G_CmCallbackCookie);
		G_CmCallbackActive = FALSE;
		G_CmCallbackCookie.QuadPart = 0;
		LogMessage("CmCallback unregistered.\n");
	}

	if (G_ObCallbacksActive && G_ObCallbackHandle != NULL)
	{
		ObUnRegisterCallbacks(G_ObCallbackHandle);
		G_ObCallbacksActive = FALSE;
		G_ObCallbackHandle = NULL;
		LogMessage("ObCallbacks unregistered.\n");
	}
}
