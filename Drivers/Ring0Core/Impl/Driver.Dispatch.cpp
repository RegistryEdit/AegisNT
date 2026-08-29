
_Use_decl_annotations_
NTSTATUS
DispatchCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;

	if (IrpSp->MajorFunction == IRP_MJ_CREATE)
	{
		Status = VerifyRequestorImageSignature(Irp);
		if (NT_SUCCESS(Status))
			IrpSp->FileObject->FsContext = MDV_AUTHORIZED_FILE_CONTEXT;
		else
			LogMessage("Denied device open from unapproved image (status 0x%08X).\n", Status);
	}
	else if (IrpSp->FileObject != NULL)
	{
		IrpSp->FileObject->FsContext = NULL;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

_Use_decl_annotations_
NTSTATUS
DispatchDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS            Status = STATUS_SUCCESS;
	ULONG               BytesReturned = 0;
	PIO_STACK_LOCATION  IrpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG               IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	PVOID               InputBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG               InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (IrpSp->FileObject == NULL ||
		IrpSp->FileObject->FsContext != MDV_AUTHORIZED_FILE_CONTEXT)
	{
		Status = STATUS_ACCESS_DENIED;
		goto CompleteRequest;
	}

	switch (IoControlCode)
	{
	case IOCTL_KILL_PROCESS:
	{
		if (InputBuffer == NULL || InputLength < sizeof(KILL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PKILL_PROCESS_INPUT Input = static_cast<PKILL_PROCESS_INPUT>(InputBuffer);
		if (Input->ProcessId == 0 || Input->ProcessId == 4)
		{
			Status = STATUS_ACCESS_DENIED;
			break;
		}
		Status = ForceTerminateProcess(Input->ProcessId);
		BytesReturned = sizeof(KILL_PROCESS_INPUT);
		break;
	}

	case IOCTL_ADD_PROCESS_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PROCESS_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPROCESS_PROTECT_INPUT Input = static_cast<PPROCESS_PROTECT_INPUT>(InputBuffer);
		Status = AddProcessToProtectionList(Input->ProcessId);
		BytesReturned = sizeof(PROCESS_PROTECT_INPUT);
		break;
	}

	case IOCTL_REMOVE_PROCESS_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PROCESS_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPROCESS_PROTECT_INPUT Input = static_cast<PPROCESS_PROTECT_INPUT>(InputBuffer);
		Status = RemoveProcessFromProtectionList(Input->ProcessId);
		BytesReturned = sizeof(PROCESS_PROTECT_INPUT);
		break;
	}

	case IOCTL_ADD_REGISTRY_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(REGISTRY_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PREGISTRY_PROTECT_INPUT Input = static_cast<PREGISTRY_PROTECT_INPUT>(InputBuffer);
		Input->KeyPath[255] = L'\0';
		Status = AddRegistryPathToProtectionList(Input->KeyPath);
		BytesReturned = sizeof(REGISTRY_PROTECT_INPUT);
		break;
	}

	case IOCTL_REMOVE_REGISTRY_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(REGISTRY_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PREGISTRY_PROTECT_INPUT Input = static_cast<PREGISTRY_PROTECT_INPUT>(InputBuffer);
		Input->KeyPath[255] = L'\0';
		Status = RemoveRegistryPathFromProtectionList(Input->KeyPath);
		BytesReturned = sizeof(REGISTRY_PROTECT_INPUT);
		break;
	}

	case IOCTL_ADD_FILE_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(FILE_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PFILE_PROTECT_INPUT Input = static_cast<PFILE_PROTECT_INPUT>(InputBuffer);
		Input->FilePath[259] = L'\0';
		Status = AddFilePathToProtectionList(Input->FilePath);
		BytesReturned = sizeof(FILE_PROTECT_INPUT);
		break;
	}

	case IOCTL_REMOVE_FILE_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(FILE_PROTECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PFILE_PROTECT_INPUT Input = static_cast<PFILE_PROTECT_INPUT>(InputBuffer);
		Input->FilePath[259] = L'\0';
		Status = RemoveFilePathFromProtectionList(Input->FilePath);
		BytesReturned = sizeof(FILE_PROTECT_INPUT);
		break;
	}

	case IOCTL_SET_PPL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PPL_CONTROL_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPPL_CONTROL_INPUT Input = static_cast<PPPL_CONTROL_INPUT>(InputBuffer);
		if (Input->RemoveProtection)
			Status = RemoveProcessPpl(Input->ProcessId);
		else
			Status = SetProcessPpl(Input->ProcessId,
				Input->ProtectionType, Input->ProtectionSigner, Input->Audit);
		BytesReturned = sizeof(PPL_CONTROL_INPUT);
		break;
	}

	case IOCTL_REMOVE_PPL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PPL_CONTROL_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPPL_CONTROL_INPUT Input = static_cast<PPPL_CONTROL_INPUT>(InputBuffer);
		Status = RemoveProcessPpl(Input->ProcessId);
		BytesReturned = sizeof(PPL_CONTROL_INPUT);
		break;
	}

	case IOCTL_CLEAR_ALL_PROTECTION:
	{
		ClearAllProtectionLists();
		Status = STATUS_SUCCESS;
		BytesReturned = 0;
		break;
	}

	case IOCTL_REMOVE_ALL_OBCALLBACKS:
	{
		Status = RemoveAllObCallbacks();
		BytesReturned = 0;
		break;
	}

	case IOCTL_REMOVE_ALL_REGISTRYCALLBACKS:
	{
		Status = RemoveAllRegistryCallbacks();
		BytesReturned = 0;
		break;
	}

	case IOCTL_REMOVE_ALL_FILTERS:
	{
		Status = RemoveAllFilters();
		BytesReturned = 0;
		break;
	}

	case IOCTL_ENUM_CALLBACKS:
	{
		Status = EnumerateAllCallbacks(
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_REMOVE_CALLBACK_BY_ADDRESS:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CALLBACK_REMOVE_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCALLBACK_REMOVE_INPUT Input = static_cast<PCALLBACK_REMOVE_INPUT>(InputBuffer);
		Status = RemoveCallbackByAddress(Input->Type, Input->Address);
		BytesReturned = sizeof(CALLBACK_REMOVE_INPUT);
		break;
	}

	case IOCTL_QUERY_PPL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PPL_QUERY_INPUT)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PPL_QUERY_OUTPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPPL_QUERY_INPUT  Input = static_cast<PPPL_QUERY_INPUT>(InputBuffer);
		PPPL_QUERY_OUTPUT Output = static_cast<PPPL_QUERY_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		Status = QueryProcessPpl(Input->ProcessId, Output);
		BytesReturned = sizeof(PPL_QUERY_OUTPUT);
		break;
	}

	case IOCTL_SET_CRITICAL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = SetProcessCritical(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_REMOVE_CRITICAL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = RemoveProcessCritical(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_HIDE_PROCESS:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = HideProcess(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_UNHIDE_PROCESS:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = UnhideProcess(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_FORCE_DELETE_FILE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(FORCE_DELETE_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PFORCE_DELETE_INPUT Input = static_cast<PFORCE_DELETE_INPUT>(InputBuffer);
		Input->FilePath[259] = L'\0';
		Status = ForceDeleteFile(Input->FilePath);
		BytesReturned = sizeof(FORCE_DELETE_INPUT);
		break;
	}

	case IOCTL_ADJUST_PRIVILEGES:
	{
		if (InputBuffer == NULL || InputLength < sizeof(PRIVILEGE_ADJUST_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PPRIVILEGE_ADJUST_INPUT Input = static_cast<PPRIVILEGE_ADJUST_INPUT>(InputBuffer);
		Status = AdjustProcessPrivileges(Input->ProcessId, &Input->PrivilegeLuid, Input->Enable);
		BytesReturned = sizeof(PRIVILEGE_ADJUST_INPUT);
		break;
	}

	case IOCTL_QUEUE_APC:
	{
		if (InputBuffer == NULL || InputLength < sizeof(APC_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PAPC_INPUT Input = static_cast<PAPC_INPUT>(InputBuffer);
		Status = QueueProcessApc(Input->ProcessId, Input->ApcAction);
		BytesReturned = sizeof(APC_INPUT);
		break;
	}

	case IOCTL_ENUM_PROCESSES:
	{
		Status = EnumerateProcesses(
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_DISABLE_APC:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = DisableProcessApc(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_ENABLE_APC:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = EnableProcessApc(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_TERMINATE_THREAD:
	{
		if (InputBuffer == NULL || InputLength < sizeof(TERMINATE_THREAD_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTERMINATE_THREAD_INPUT Input = static_cast<PTERMINATE_THREAD_INPUT>(InputBuffer);
		if (Input->ProcessId == 0 || Input->ThreadId == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = ForceTerminateThread(Input->ThreadId, Input->ProcessId);
		BytesReturned = sizeof(TERMINATE_THREAD_INPUT);
		break;
	}

	case IOCTL_TERMINATE_PROCESS_MEMORY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(TERMINATE_PROCESS_MEMORY_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTERMINATE_PROCESS_MEMORY_INPUT Input = static_cast<PTERMINATE_PROCESS_MEMORY_INPUT>(InputBuffer);
		if (Input->ProcessId == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = WriteZeroMemoryToProcess(Input->ProcessId);
		BytesReturned = sizeof(TERMINATE_PROCESS_MEMORY_INPUT);
		break;
	}

	case IOCTL_TERMINATE_PROCESS_THREADS:
	{
		if (InputBuffer == NULL ||
			InputLength < sizeof(TERMINATE_PROCESS_THREADS_INPUT) ||
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(TERMINATE_PROCESS_THREADS_OUTPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTERMINATE_PROCESS_THREADS_INPUT Input =
			static_cast<PTERMINATE_PROCESS_THREADS_INPUT>(InputBuffer);
		PTERMINATE_PROCESS_THREADS_OUTPUT Output =
			static_cast<PTERMINATE_PROCESS_THREADS_OUTPUT>(
				Irp->AssociatedIrp.SystemBuffer);
		if (Input->ProcessId == 0 || Input->ProcessId == 4)
		{
			Status = STATUS_ACCESS_DENIED;
			break;
		}
		Status = ForceTerminateProcessThreads(Input->ProcessId, Output);
		if (!NT_SUCCESS(Status))
			Output->LastStatus = Status;
		BytesReturned = sizeof(TERMINATE_PROCESS_THREADS_OUTPUT);
		break;
	}

	case IOCTL_STEAL_TOKEN:
	{
		if (InputBuffer == NULL || InputLength < sizeof(STEAL_TOKEN_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PSTEAL_TOKEN_INPUT Input = static_cast<PSTEAL_TOKEN_INPUT>(InputBuffer);
		if (Input->SourceProcessId == 0 || Input->TargetProcessId == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = SetToken(Input->SourceProcessId, Input->TargetProcessId);
		BytesReturned = sizeof(STEAL_TOKEN_INPUT);
		break;
	}

	case IOCTL_LAUNCH_AS:
	{
		if (InputBuffer == NULL || InputLength < sizeof(LAUNCH_AS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		PLAUNCH_AS_INPUT Input = static_cast<PLAUNCH_AS_INPUT>(InputBuffer);
		Input->ImagePath[259] = L'\0';
		Input->ProcessId = 0;
		Input->ThreadId = 0;
		Input->ErrorCode = 0;

		Status = LaunchAs(
			Input->AccountType,
			Input->ImagePath,
			&Input->ProcessId,
			&Input->ThreadId
		);

		if (!NT_SUCCESS(Status))
		{
			Input->ErrorCode = Status;
		}

		BytesReturned = sizeof(LAUNCH_AS_INPUT);
		break;
	}

	case IOCTL_VERIFY:
	{
		
		Status = STATUS_SUCCESS;
		BytesReturned = 0;
		break;
	}

	case IOCTL_READ_MEMORY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(MEMORY_READ_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PMEMORY_READ_INPUT Input = static_cast<PMEMORY_READ_INPUT>(InputBuffer);

		ULONG OutputLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
		if (OutputLen <= sizeof(MEMORY_READ_INPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		ULONG MaxRead = OutputLen - sizeof(MEMORY_READ_INPUT);
		ULONG ReadSize = Input->Size;
		if (ReadSize > MaxRead)
			ReadSize = MaxRead;

		PVOID DataBuffer = reinterpret_cast<PUCHAR>(InputBuffer) + sizeof(MEMORY_READ_INPUT);
		Status = ReadMemory(Input->ProcessId, Input->Address, ReadSize, DataBuffer);
		BytesReturned = sizeof(MEMORY_READ_INPUT) + ReadSize;
		break;
	}

	case IOCTL_WRITE_MEMORY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(MEMORY_WRITE_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PMEMORY_WRITE_INPUT Input = static_cast<PMEMORY_WRITE_INPUT>(InputBuffer);

		ULONG WriteSize = Input->Size;
		if (WriteSize == 0)
		{
			Status = STATUS_SUCCESS;
			BytesReturned = sizeof(MEMORY_WRITE_INPUT);
			break;
		}
		if (InputLength < sizeof(MEMORY_WRITE_INPUT) + WriteSize)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		PVOID DataBuffer = reinterpret_cast<PUCHAR>(InputBuffer) + sizeof(MEMORY_WRITE_INPUT);
		Status = WriteMemory(Input->ProcessId, Input->Address, WriteSize, DataBuffer);
		BytesReturned = sizeof(MEMORY_WRITE_INPUT);
		break;
	}

	case IOCTL_QUERY_SYSTEM_TABLES:
	{
		PSYSTEM_TABLES_OUTPUT Output = static_cast<PSYSTEM_TABLES_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = QuerySystemTables(Output,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_ENUM_SYSTEM_TABLE_ENTRIES:
	{
		PSYSTEM_TABLE_ENTRIES_OUTPUT Output = static_cast<PSYSTEM_TABLE_ENTRIES_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		const ULONG TableKind = (InputBuffer != NULL && InputLength >= sizeof(ULONG))
			? *static_cast<PULONG>(InputBuffer) : MAXULONG;
		Status = EnumerateSystemTableEntries(TableKind, Output,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		break;
	}

	case IOCTL_ENUM_PIDDB_CACHE:
	{
		PPIDDB_CACHE_ENUM_OUTPUT Output = static_cast<PPIDDB_CACHE_ENUM_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = EnumeratePiDDBCache(Output,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		break;
	}

	case IOCTL_ENUM_DRIVERS:
	{
		Status = EnumerateDrivers(Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		break;
	}

	case IOCTL_LOAD_DRIVER:
	{
		if (InputBuffer == NULL || InputLength < sizeof(DRIVER_CONTROL_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = LoadDriverKernel(static_cast<PDRIVER_CONTROL_INPUT>(InputBuffer),
			static_cast<PDRIVER_CONTROL_OUTPUT>(Irp->AssociatedIrp.SystemBuffer),
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		break;
	}

	case IOCTL_UNLOAD_DRIVER:
	{
		if (InputBuffer == NULL || InputLength < sizeof(DRIVER_CONTROL_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = UnloadDriverKernel(static_cast<PDRIVER_CONTROL_INPUT>(InputBuffer),
			static_cast<PDRIVER_CONTROL_OUTPUT>(Irp->AssociatedIrp.SystemBuffer),
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		break;
	}

	case IOCTL_SET_PREVIOUS_MODE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(CRITICAL_PROCESS_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PCRITICAL_PROCESS_INPUT Input = static_cast<PCRITICAL_PROCESS_INPUT>(InputBuffer);
		Status = SetProcessPreviousMode(Input->ProcessId);
		BytesReturned = sizeof(CRITICAL_PROCESS_INPUT);
		break;
	}

	case IOCTL_QUERY_CAPABILITIES_V2:
	case IOCTL_QUERY_PROCESS_V2:
	case IOCTL_QUERY_EPROCESS_V2:
	case IOCTL_ENUM_THREADS_V2:
	case IOCTL_ENUM_HANDLES_V2:
	case IOCTL_ENUM_MODULES_V2:
	case IOCTL_ENUM_MEMORY_V2:
	case IOCTL_QUERY_MEMORY_V2:
	case IOCTL_ENUM_BIG_POOL_V2:
	case IOCTL_ENUM_OBJECTS_V2:
	case IOCTL_ENUM_KERNEL_MODULES_V2:
	case IOCTL_QUERY_DRIVER_V2:
	case IOCTL_ENUM_MINIFILTERS_V2:
	case IOCTL_ENUM_WFP_V2:
	case IOCTL_ENUM_NDIS_V2:
	case IOCTL_QUERY_SECURITY_V2:
	case IOCTL_QUERY_ADVANCED_V3:
	{
		PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (METHOD_FROM_CTL_CODE(IoControlCode) == METHOD_OUT_DIRECT) {
			if (Irp->MdlAddress == NULL) { Status = STATUS_INVALID_PARAMETER; break; }
			OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
			if (OutputBuffer == NULL) { Status = STATUS_INSUFFICIENT_RESOURCES; break; }
		}
		if (IoControlCode == IOCTL_QUERY_ADVANCED_V3) {
			if (InputBuffer == NULL || InputLength < sizeof(MDV2_QUERY_INPUT)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (OutputBuffer == NULL ||
				IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MDV2_LIST_HEADER)) {
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			Status = AdvancedQuery(static_cast<const MDV2_QUERY_INPUT*>(InputBuffer),
				static_cast<PMDV2_LIST_OUTPUT>(OutputBuffer),
				IrpSp->Parameters.DeviceIoControl.OutputBufferLength);
			if (OutputBuffer != NULL &&
				IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(MDV2_LIST_HEADER))
				BytesReturned = static_cast<PMDV2_LIST_OUTPUT>(OutputBuffer)->Header.RequiredSize;
		} else {
			Status = Mdv2DispatchInventory(IoControlCode, Irp->AssociatedIrp.SystemBuffer,
				InputLength, OutputBuffer, IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &BytesReturned);
		}
		break;
	}

	case IOCTL_ADVANCED_OPERATION_V3:
	{
		const ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
		if (InputBuffer == NULL || InputLength < sizeof(ADVANCED_OPERATION_INPUT)) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (OutputLength < sizeof(ADVANCED_OPERATION_OUTPUT)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		ADVANCED_OPERATION_INPUT Input =
			*static_cast<PADVANCED_OPERATION_INPUT>(InputBuffer);
		Status = AdvancedOperation(&Input,
			static_cast<PADVANCED_OPERATION_OUTPUT>(InputBuffer));
		BytesReturned = sizeof(ADVANCED_OPERATION_OUTPUT);
		break;
	}

	case IOCTL_KERNEL_READ_MEMORY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(KERNEL_READ_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		ULONG OutputLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
		if (OutputLen <= sizeof(KERNEL_READ_OUTPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PKERNEL_READ_INPUT  Input  = static_cast<PKERNEL_READ_INPUT>(InputBuffer);
		PKERNEL_READ_OUTPUT Output = static_cast<PKERNEL_READ_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);

		ULONG MaxRead = OutputLen - sizeof(KERNEL_READ_OUTPUT);
		ULONG ReadSize = Input->Size;
		if (ReadSize > MaxRead)
			ReadSize = MaxRead;

		PVOID DataBuffer = reinterpret_cast<PUCHAR>(Output) + sizeof(KERNEL_READ_OUTPUT);
		NTSTATUS ReadStatus = KrnlReadMemory(
			reinterpret_cast<PVOID>(Input->Address),
			DataBuffer,
			ReadSize);

		Output->BytesRead = NT_SUCCESS(ReadStatus) ? ReadSize : 0;
		Output->Status    = ReadStatus;
		BytesReturned = sizeof(KERNEL_READ_OUTPUT) + ReadSize;
		break;
	}

	case IOCTL_KERNEL_WRITE_MEMORY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(KERNEL_WRITE_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		PKERNEL_WRITE_INPUT Input = static_cast<PKERNEL_WRITE_INPUT>(InputBuffer);

		ULONG WriteSize = Input->Size;
		if (WriteSize == 0)
		{
			Status = STATUS_SUCCESS;
			BytesReturned = sizeof(KERNEL_WRITE_INPUT);
			break;
		}

		if (InputLength < sizeof(KERNEL_WRITE_INPUT) + WriteSize)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		PVOID DataBuffer = reinterpret_cast<PUCHAR>(InputBuffer) + sizeof(KERNEL_WRITE_INPUT);
		Status = KrnlWriteMemory(
			reinterpret_cast<PVOID>(Input->Address),
			DataBuffer,
			WriteSize,
			Input->Method);
		BytesReturned = sizeof(KERNEL_WRITE_INPUT);
		break;
	}

	case IOCTL_DISABLE_DSE:
	{
		PDSE_CONTROL_OUTPUT Output = static_cast<PDSE_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlDisableDse(Output);
		BytesReturned = sizeof(DSE_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_RESTORE_DSE:
	{
		PDSE_CONTROL_OUTPUT Output = static_cast<PDSE_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlRestoreDse(Output);
		BytesReturned = sizeof(DSE_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_QUERY_DSE:
	{
		PDSE_CONTROL_OUTPUT Output = static_cast<PDSE_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlQueryDse(Output);
		BytesReturned = sizeof(DSE_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_DLL_INJECT_APC:
	{
		if (InputBuffer == NULL || InputLength < sizeof(DLL_INJECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PDLL_INJECT_INPUT Input = static_cast<PDLL_INJECT_INPUT>(InputBuffer);
		Input->DllPath[259] = L'\0';
		Status = DllInjectApc(Input->ProcessId, Input->DllPath);
		BytesReturned = sizeof(DLL_INJECT_INPUT);
		break;
	}

	case IOCTL_DLL_INJECT_THREAD:
	{
		if (InputBuffer == NULL || InputLength < sizeof(DLL_INJECT_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PDLL_INJECT_INPUT Input = static_cast<PDLL_INJECT_INPUT>(InputBuffer);
		Input->DllPath[259] = L'\0';
		Status = DllInjectThread(Input->ProcessId, Input->DllPath);
		BytesReturned = sizeof(DLL_INJECT_INPUT);
		break;
	}

	case IOCTL_ENABLE_DEBUG:
	{
		Status = KrnlEnableDebug();
		BytesReturned = 0;
		break;
	}

	case IOCTL_DISABLE_DEBUG:
	{
		Status = KrnlDisableDebug();
		BytesReturned = 0;
		break;
	}

	case IOCTL_QUERY_DEBUG_STATE:
	{
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DEBUG_STATE_OUTPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		PDEBUG_STATE_OUTPUT Output = static_cast<PDEBUG_STATE_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlQueryDebug(Output);
		BytesReturned = sizeof(DEBUG_STATE_OUTPUT);
		break;
	}

	case IOCTL_ENUM_WINDOWS:
	{
		Status = EnumerateWindowsKernel(
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_WINDOW_OPERATION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(WINDOW_OPERATION_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PWINDOW_OPERATION_INPUT Input = static_cast<PWINDOW_OPERATION_INPUT>(InputBuffer);
		Input->NewTitle[255] = L'\0';
		Status = WindowOperation(Input);
		BytesReturned = sizeof(WINDOW_OPERATION_INPUT);
		break;
	}

	case IOCTL_GET_COMMAND_LINE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(COMMAND_LINE_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PCOMMAND_LINE_INPUT CmdInput = static_cast<PCOMMAND_LINE_INPUT>(InputBuffer);
		Status = GetCmdLine(CmdInput,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_SERVICE_OPERATION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(SERVICE_OPERATION_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PSERVICE_OPERATION_INPUT SvcInput = static_cast<PSERVICE_OPERATION_INPUT>(InputBuffer);
		SvcInput->ServiceName[127] = L'\0';
		Status = ServiceOperation(SvcInput,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_REG_OPERATION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(REG_OPERATION_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PREG_OPERATION_INPUT RegInput = static_cast<PREG_OPERATION_INPUT>(InputBuffer);
		PVOID ExtraData = (PUCHAR)InputBuffer + sizeof(REG_OPERATION_INPUT);
		ULONG ExtraSize = (InputLength > sizeof(REG_OPERATION_INPUT)) ? (InputLength - sizeof(REG_OPERATION_INPUT)) : 0;
		Status = RegOperation(RegInput, ExtraData, ExtraSize,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_SESSION_OPERATION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(SESSION_OPERATION_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PSESSION_OPERATION_INPUT SessInput = static_cast<PSESSION_OPERATION_INPUT>(InputBuffer);
		Status = SessionOperation(SessInput,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_MITIGATION_QUERY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(ULONG))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		ULONG MitPid = *(PULONG)InputBuffer;
		Status = QueryMitigation(MitPid,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_MITIGATION_SET:
	{
		if (InputBuffer == NULL || InputLength < sizeof(MITIGATION_SET_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PMITIGATION_SET_INPUT MitInput = static_cast<PMITIGATION_SET_INPUT>(InputBuffer);
		Status = SetMitigation(MitInput);
		BytesReturned = sizeof(MITIGATION_SET_INPUT);
		break;
	}

	case IOCTL_ENUM_SYNC_OBJECTS:
	{
		PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (Irp->MdlAddress == NULL) { Status = STATUS_INVALID_PARAMETER; break; }
		OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
		if (OutputBuffer == NULL) { Status = STATUS_INSUFFICIENT_RESOURCES; break; }
		Status = EnumerateSyncObjects(
			OutputBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_ADD_WINDOW_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(WINDOW_PROTECT_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PWINDOW_PROTECT_INPUT WinProt = static_cast<PWINDOW_PROTECT_INPUT>(InputBuffer);
		Status = AddWindowProtect(WinProt);
		BytesReturned = sizeof(WINDOW_PROTECT_INPUT);
		break;
	}

	case IOCTL_REMOVE_WINDOW_PROTECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(WINDOW_PROTECT_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PWINDOW_PROTECT_INPUT WinProt = static_cast<PWINDOW_PROTECT_INPUT>(InputBuffer);
		Status = RemoveWindowProtect(WinProt);
		BytesReturned = sizeof(WINDOW_PROTECT_INPUT);
		break;
	}

	case IOCTL_ADD_INJECTION_PROTECTION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(INJECTION_PROTECT_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PINJECTION_PROTECT_INPUT InjProt = static_cast<PINJECTION_PROTECT_INPUT>(InputBuffer);
		Status = AddInjectionProtect(InjProt);
		BytesReturned = sizeof(INJECTION_PROTECT_INPUT);
		break;
	}

	case IOCTL_REMOVE_INJECTION_PROTECTION:
	{
		if (InputBuffer == NULL || InputLength < sizeof(INJECTION_PROTECT_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PINJECTION_PROTECT_INPUT InjProt = static_cast<PINJECTION_PROTECT_INPUT>(InputBuffer);
		Status = RemoveInjectionProtect(InjProt);
		BytesReturned = sizeof(INJECTION_PROTECT_INPUT);
		break;
	}

	case IOCTL_HANDLE_CLOSE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(HANDLE_CLOSE_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PHANDLE_CLOSE_INPUT Input = static_cast<PHANDLE_CLOSE_INPUT>(InputBuffer);
		if (Input->ProcessId == 0 || Input->HandleValue == 0)
		{ Status = STATUS_INVALID_PARAMETER; break; }
		Status = ForceCloseHandle(Input->ProcessId, Input->HandleValue);
		BytesReturned = sizeof(HANDLE_CLOSE_INPUT);
		break;
	}

	case IOCTL_HANDLE_DOWNGRADE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(HANDLE_DOWNGRADE_INPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PHANDLE_DOWNGRADE_INPUT Input = static_cast<PHANDLE_DOWNGRADE_INPUT>(InputBuffer);
		if (Input->ProcessId == 0 || Input->HandleValue == 0)
		{ Status = STATUS_INVALID_PARAMETER; break; }
		Input->NewHandleValue = 0;
		Status = DowngradeHandle(Input);
		BytesReturned = sizeof(HANDLE_DOWNGRADE_INPUT);
		break;
	}

	case IOCTL_HANDLE_DUP_DOWNGRADE:
	{
		if (InputBuffer == NULL || InputLength < sizeof(HANDLE_DUP_DOWNGRADE_INPUT)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HANDLE_DUP_DOWNGRADE_OUTPUT))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PHANDLE_DUP_DOWNGRADE_INPUT Input = static_cast<PHANDLE_DUP_DOWNGRADE_INPUT>(InputBuffer);
		PHANDLE_DUP_DOWNGRADE_OUTPUT Output = static_cast<PHANDLE_DUP_DOWNGRADE_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		if (Input->SourceProcessId == 0 || Input->SourceHandle == 0 || Input->TargetProcessId == 0)
		{ Status = STATUS_INVALID_PARAMETER; break; }
		Status = DuplicateAndDowngradeHandle(
			Input->SourceProcessId, Input->SourceHandle,
			Input->TargetProcessId, Input->NewAccess, Output);
		BytesReturned = sizeof(HANDLE_DUP_DOWNGRADE_OUTPUT);
		break;
	}

	case IOCTL_DISABLE_PATCHGUARD:
	{
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PG_CONTROL_OUTPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		PPG_CONTROL_OUTPUT Output = static_cast<PPG_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlDisablePg(Output);
		BytesReturned = sizeof(PG_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_RESTORE_PATCHGUARD:
	{
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PG_CONTROL_OUTPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		PPG_CONTROL_OUTPUT Output = static_cast<PPG_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlRestorePg(Output);
		BytesReturned = sizeof(PG_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_QUERY_PATCHGUARD:
	{
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PG_CONTROL_OUTPUT))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		PPG_CONTROL_OUTPUT Output = static_cast<PPG_CONTROL_OUTPUT>(
			Irp->AssociatedIrp.SystemBuffer);
		Status = KrnlQueryPg(Output);
		BytesReturned = sizeof(PG_CONTROL_OUTPUT);
		break;
	}

	case IOCTL_SET_IDT_LIMIT:
	{
		ExecutePatchGuard();
		break;
	}

	case IOCTL_THREAD_HIJACK_CONTEXT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(THREAD_HIJACK_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTHREAD_HIJACK_INPUT Input = static_cast<PTHREAD_HIJACK_INPUT>(InputBuffer);
		if (Input->ThreadId == 0 || Input->TargetRip == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = HijackThreadContext(Input->ThreadId, Input->TargetRip);
		BytesReturned = sizeof(THREAD_HIJACK_INPUT);
		break;
	}

	case IOCTL_THREAD_HIJACK_TRAPFRAME:
	{
		if (InputBuffer == NULL || InputLength < sizeof(THREAD_HIJACK_INPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTHREAD_HIJACK_INPUT Input = static_cast<PTHREAD_HIJACK_INPUT>(InputBuffer);
		if (Input->ThreadId == 0 || Input->TargetRip == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = HijackThreadTrapFrame(Input->ThreadId, Input->TargetRip);
		BytesReturned = sizeof(THREAD_HIJACK_INPUT);
		break;
	}

	case IOCTL_THREAD_REMOTE_CALL:
	{
		if (InputBuffer == NULL || InputLength < sizeof(THREAD_REMOTE_CALL_INPUT)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(THREAD_REMOTE_CALL_OUTPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PTHREAD_REMOTE_CALL_INPUT  Input  = static_cast<PTHREAD_REMOTE_CALL_INPUT>(InputBuffer);
		PTHREAD_REMOTE_CALL_OUTPUT Output = static_cast<PTHREAD_REMOTE_CALL_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		if (Input->ThreadId == 0 || Input->Function == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		Status = RemoteCallInThread(
			Input->ThreadId, Input->Function,
			Input->Args[0], Input->Args[1],
			Input->Args[2], Input->Args[3],
			&Output->Result);
		BytesReturned = sizeof(THREAD_REMOTE_CALL_OUTPUT);
		break;
	}

	case IOCTL_THREAD_SHELLCODE_INJECT:
	{
		if (InputBuffer == NULL || InputLength < sizeof(SHELLCODE_INJECT_INPUT)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SHELLCODE_INJECT_OUTPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PSHELLCODE_INJECT_INPUT  Input  = static_cast<PSHELLCODE_INJECT_INPUT>(InputBuffer);
		PSHELLCODE_INJECT_OUTPUT Output = static_cast<PSHELLCODE_INJECT_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		if (Input->Id == 0 || Input->Size == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		ULONG DataSize = Input->Size;
		if (InputLength < sizeof(SHELLCODE_INJECT_INPUT) + DataSize)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PUCHAR ShellcodeData = reinterpret_cast<PUCHAR>(InputBuffer) + sizeof(SHELLCODE_INJECT_INPUT);
		ULONG_PTR AllocAddr = 0;
		Status = InjectShellcode(Input->Id, ShellcodeData, DataSize, &AllocAddr);
		Output->AllocatedAddress = AllocAddr;
		Output->Status = Status;
		BytesReturned = sizeof(SHELLCODE_INJECT_OUTPUT);
		break;
	}

	case IOCTL_THREAD_INJECT_AND_HIJACK:
	{
		if (InputBuffer == NULL || InputLength < sizeof(SHELLCODE_INJECT_INPUT)
			|| IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SHELLCODE_INJECT_OUTPUT))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PSHELLCODE_INJECT_INPUT  Input  = static_cast<PSHELLCODE_INJECT_INPUT>(InputBuffer);
		PSHELLCODE_INJECT_OUTPUT Output = static_cast<PSHELLCODE_INJECT_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		if (Input->Id == 0 || Input->Size == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		ULONG DataSize = Input->Size;
		if (InputLength < sizeof(SHELLCODE_INJECT_INPUT) + DataSize)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PUCHAR ShellcodeData = reinterpret_cast<PUCHAR>(InputBuffer) + sizeof(SHELLCODE_INJECT_INPUT);
		ULONG_PTR AllocAddr = 0;
		Status = InjectAndHijack(Input->Id, ShellcodeData, DataSize, &AllocAddr);
		Output->AllocatedAddress = AllocAddr;
		Output->Status = Status;
		BytesReturned = sizeof(SHELLCODE_INJECT_OUTPUT);
		break;
	}

	case IOCTL_HOOK_QUERY_CAPABILITIES:
	{
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HOOK_CAPABILITIES_OUTPUT))
		{ Status = STATUS_BUFFER_TOO_SMALL; break; }
		PHOOK_CAPABILITIES_OUTPUT Output = static_cast<PHOOK_CAPABILITIES_OUTPUT>(Irp->AssociatedIrp.SystemBuffer);
		Output->Size = sizeof(HOOK_CAPABILITIES_OUTPUT);
		Status = HookQueryCapabilities(Output);
		Output->LastStatus = Status;
		BytesReturned = sizeof(HOOK_CAPABILITIES_OUTPUT);
		break;
	}

	case IOCTL_HOOK_ENUM:
	{
		Status = HookEnumerate(Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
			&BytesReturned);
		break;
	}

	case IOCTL_HOOK_INSTALL:
	case IOCTL_HOOK_ENABLE:
	case IOCTL_HOOK_DISABLE:
	case IOCTL_HOOK_REMOVE:
	case IOCTL_HOOK_VERIFY:
	{
		if (InputBuffer == NULL || InputLength < sizeof(HOOK_REQUEST) ||
			IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HOOK_RECORD))
		{ Status = STATUS_INVALID_PARAMETER; break; }
		PHOOK_REQUEST Input = static_cast<PHOOK_REQUEST>(InputBuffer);
		PHOOK_RECORD Output = static_cast<PHOOK_RECORD>(Irp->AssociatedIrp.SystemBuffer);
		if (Input->Size == 0)
			Input->Size = sizeof(HOOK_REQUEST);
		if (Input->Operation == 0)
			Input->Operation = IoControlCode == IOCTL_HOOK_INSTALL ? HOOK_OP_INSTALL :
				(IoControlCode == IOCTL_HOOK_ENABLE ? HOOK_OP_ENABLE :
				 (IoControlCode == IOCTL_HOOK_DISABLE ? HOOK_OP_DISABLE :
				  (IoControlCode == IOCTL_HOOK_REMOVE ? HOOK_OP_REMOVE : HOOK_OP_VERIFY)));
		Status = HookOperate(Input, Output);
		Output->Status = Status;
		BytesReturned = sizeof(HOOK_RECORD);
		break;
	}

	case IOCTL_HOOK_RESTORE_ALL:
	{
		Status = HookRestoreAll();
		BytesReturned = 0;
		break;
	}

	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

CompleteRequest:
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

_Use_decl_annotations_
NTSTATUS
DispatchShutdown(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
