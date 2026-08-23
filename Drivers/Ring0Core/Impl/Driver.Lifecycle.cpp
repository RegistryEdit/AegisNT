
_Use_decl_annotations_
static NTSTATUS
DispatchCreateRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_SentinelDeviceObject)
		return IrpCreate(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvControlDevice)
		return DiskDrvControlCreate(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterPassThrough(DeviceObject, Irp);
	return DispatchCreateClose(DeviceObject, Irp);
}

_Use_decl_annotations_
static NTSTATUS
DispatchCloseRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_SentinelDeviceObject)
		return IrpClose(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvControlDevice)
		return DiskDrvControlClose(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterPassThrough(DeviceObject, Irp);
	return DispatchCreateClose(DeviceObject, Irp);
}

_Use_decl_annotations_
static NTSTATUS
DispatchControlRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_SentinelDeviceObject)
		return IrpDeviceControl(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvControlDevice)
		return DiskDrvControlDeviceControl(DeviceObject, Irp);
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterDeviceControl(DeviceObject, Irp);
	return DispatchDeviceControl(DeviceObject, Irp);
}

_Use_decl_annotations_
static NTSTATUS
DispatchWriteRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterWrite(DeviceObject, Irp);
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
}

_Use_decl_annotations_
static NTSTATUS
DispatchPowerRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterPower(DeviceObject, Irp);
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
}

_Use_decl_annotations_
static NTSTATUS
DispatchShutdownRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterPassThrough(DeviceObject, Irp);
	return DispatchShutdown(DeviceObject, Irp);
}

_Use_decl_annotations_
static NTSTATUS
DispatchFilterPassRouter(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	if (DeviceObject == G_DiskDrvFilterDevice)
		return DiskDrvFilterPassThrough(DeviceObject, Irp);
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	KeInitializeSpinLock(&G_AdvancedTransactionLock);
	KeInitializeSpinLock(&G_HookLock);
	RtlZeroMemory(G_HookSlots, sizeof(G_HookSlots));
	G_NextHookId = 1;
	PAGED_CODE();

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	NTSTATUS       Status;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymLink;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\AegisCore");
	RtlInitUnicodeString(&SymLink, L"\\DosDevices\\AegisCore");

	LogMessage("Ring0Core.sys initializing...\n");

	InitializeListHead(&G_ProcessListHead);
	InitializeListHead(&G_RegistryListHead);
	InitializeListHead(&G_FileListHead);
    InitializeListHead(&G_ApcToggleListHead);
    InitializeListHead(&G_WindowListHead);
    InitializeListHead(&G_InjectionProtectListHead);
    InitializeListHead(&G_HiddenProcessListHead);
    KeInitializeSpinLock(&G_ProcessListLock);
    KeInitializeSpinLock(&G_RegistryListLock);
    KeInitializeSpinLock(&G_FileListLock);
    KeInitializeSpinLock(&G_ApcToggleListLock);
    KeInitializeSpinLock(&G_WindowListLock);
    KeInitializeSpinLock(&G_InjectionProtectListLock);
    KeInitializeSpinLock(&G_HiddenProcessListLock);

	Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_PROCESSGUARD,
		0,
		FALSE,
		&G_DeviceObject);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("IoCreateDevice(AegisCore) failed: 0x%08X\n", Status);
		return Status;
	}

	G_DeviceObject->Flags |= DO_BUFFERED_IO;
	G_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	Status = IoCreateSymbolicLink(&SymLink, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("IoCreateSymbolicLink(AegisCore) failed: 0x%08X\n", Status);
		IoDeleteDevice(G_DeviceObject);
		G_DeviceObject = NULL;
		return Status;
	}

	CreateFltRegistryConfig(RegistryPath);

	Status = CommInitialize(DriverObject);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("CommInitialize(AegisSentinel) failed: 0x%08X\n", Status);
		IoDeleteSymbolicLink(&SymLink);
		IoDeleteDevice(G_DeviceObject);
		G_DeviceObject = NULL;
		return Status;
	}

	Status = RegisterAllCallbacks();
	if (!NT_SUCCESS(Status))
	{
		LogMessage("RegisterAllCallbacks failed: 0x%08X\n", Status);
		CommCleanup();
		IoDeleteSymbolicLink(&SymLink);
		IoDeleteDevice(G_DeviceObject);
		G_DeviceObject = NULL;
		return Status;
	}

	Status = FindPplOffset(&G_PplOffset);
	if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES)
	{
		LogMessage("FindPplOffset failed (PPL features disabled): 0x%08X\n", Status);
		G_PplOffset = 0;
	}

	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"MmCopyMemory");
		G_pMmCopyMemory = (PMdvMmCopyMemory_t)MmGetSystemRoutineAddress(&RoutineName);
		if (G_pMmCopyMemory == NULL)
			LogMessage("MmCopyMemory not found, using page-by-page fallback.\n");
	}

	Callbacks::RegisterProcess();
	Callbacks::RegisterThread();
	Callbacks::RegisterImage();

	Status = RegistryMon::Register(DriverObject);
	if (!NT_SUCCESS(Status)) DRV_WARN("Registry callback failed, continuing");

	Status = ObMon::Register(DriverObject);
	if (!NT_SUCCESS(Status)) DRV_WARN("Object callback failed, continuing");

	Status = MiniFilter::Register(DriverObject);
	if (!NT_SUCCESS(Status)) DRV_WARN("Minifilter failed, continuing");

	Status = NetworkMon::Register(G_SentinelDeviceObject);
	if (!NT_SUCCESS(Status)) DRV_WARN("WFP network monitor failed, continuing");

	Status = DriverModuleMon::Register();
	if (!NT_SUCCESS(Status)) DRV_WARN("Driver unload monitor failed, continuing");

	for (ULONG Major = 0; Major <= IRP_MJ_MAXIMUM_FUNCTION; ++Major)
		DriverObject->MajorFunction[Major] = DispatchFilterPassRouter;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateRouter;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCloseRouter;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControlRouter;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWriteRouter;
	DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPowerRouter;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DispatchShutdownRouter;
	DriverObject->DriverUnload = DriverUnload;

	Status = DiskDrvInitialize(DriverObject);
	if (!NT_SUCCESS(Status)) DRV_WARN("DiskDrv subsystem failed, continuing");

	G_Initialized = TRUE;

	LogMessage("Ring0Core.sys loaded successfully.\n");

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(DriverObject);

	LogMessage("Ring0Core.sys unloading...\n");

	HookRestoreAll();
	EtwHookRemove();

	ClearAllProtectionLists();
	ClearApcToggleEntries();

	DriverModuleMon::Unregister();
	NetworkMon::Unregister();
	MiniFilter::Unregister();
	ObMon::Unregister();
	RegistryMon::Unregister();
	Callbacks::UnregisterImage();
	Callbacks::UnregisterThread();
	Callbacks::UnregisterProcess();

	UnregisterAllCallbacks();

	CommCleanup();

	DiskDrvUninitialize();

	UNICODE_STRING SymLink;
	RtlInitUnicodeString(&SymLink, L"\\DosDevices\\AegisCore");
	IoDeleteSymbolicLink(&SymLink);

	if (G_DeviceObject != NULL)
	{
		IoDeleteDevice(G_DeviceObject);
		G_DeviceObject = NULL;
	}

	G_Initialized = FALSE;
	LogMessage("Ring0Core.sys unloaded.\n");
}
