
#include <ntdddisk.h>
#include "../../DiskDrvShared.h"

#define DISKDRV_AUTHORIZED_FILE_CONTEXT ((PVOID)(ULONG_PTR)0x444B4456u) 

static constexpr ULONG kDiskDrvEventCapacity = 64;
static constexpr ULONG kDiskDrvTokenCapacity = 16;

typedef struct _DISKDRV_PENDING_REQUEST
{
    LIST_ENTRY Link;
    PIRP Irp;
    PDEVICE_OBJECT FilterDevice;
    ULONGLONG RequestId;
} DISKDRV_PENDING_REQUEST, *PDISKDRV_PENDING_REQUEST;

static PDRIVER_OBJECT G_DiskDrvDriverObject = nullptr;
static PDEVICE_OBJECT G_DiskDrvControlDevice = nullptr;
static PDEVICE_OBJECT G_DiskDrvFilterDevice = nullptr;

typedef struct _DISKDRV_ALLOW_TOKEN
{
    BOOLEAN InUse;
    ULONG DiskNumber;
    ULONG OperationType;
    ULONG ProcessId;
    ULONGLONG Offset;
    ULONGLONG Length;
    LONGLONG ExpireTick;
} DISKDRV_ALLOW_TOKEN, *PDISKDRV_ALLOW_TOKEN;

typedef struct _DISKDRV_DEVICE_EXTENSION
{
    KSPIN_LOCK Lock;
    FAST_MUTEX AttachMutex;
    PDEVICE_OBJECT ControlDevice;
    PDEVICE_OBJECT FilterDevice;
    BOOLEAN FilterAttached;
    BOOLEAN Detaching;
    ULONG DiskNumber;
    ULONG PartitionStyle;
    BOOLEAN Enabled;
    BOOLEAN AuditOnly;
    ULONG BytesPerSector;
    ULONGLONG DiskBytes;
    ULONGLONG BlockedWriteCount;
    ULONGLONG BlockedLayoutIoctlCount;
    ULONG EventWriteIndex;
    ULONG EventReadIndex;
    ULONG EventCount;
    DISKDRV_EVENT Events[kDiskDrvEventCapacity];
    DISKDRV_ALLOW_TOKEN Tokens[kDiskDrvTokenCapacity];
    LIST_ENTRY PendingRequests;
    ULONGLONG NextRequestId;
} DISKDRV_DEVICE_EXTENSION, *PDISKDRV_DEVICE_EXTENSION;

typedef struct _DISKDRV_FILTER_EXTENSION
{
    PDEVICE_OBJECT TargetDevice;
    PDISKDRV_DEVICE_EXTENSION ControlExtension;
} DISKDRV_FILTER_EXTENSION, *PDISKDRV_FILTER_EXTENSION;

static VOID DiskDrvCancelPendingWrite(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    auto *Pending = static_cast<PDISKDRV_PENDING_REQUEST>(Irp->Tail.Overlay.DriverContext[0]);
    auto *Context = static_cast<PDISKDRV_DEVICE_EXTENSION>(Irp->Tail.Overlay.DriverContext[1]);
    if (Pending != nullptr && Context != nullptr)
    {
        KIRQL OldIrql;
        KeAcquireSpinLockAtDpcLevel(&Context->Lock);
        RemoveEntryList(&Pending->Link);
        InitializeListHead(&Pending->Link);
        KeReleaseSpinLockFromDpcLevel(&Context->Lock);
        Irp->Tail.Overlay.DriverContext[0] = nullptr;
        Irp->Tail.Overlay.DriverContext[1] = nullptr;
    }
    IoReleaseCancelSpinLock(Irp->CancelIrql);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    if (Pending != nullptr)
        ExFreePoolWithTag(Pending, 'qDDA');
}

static NTSTATUS DiskDrvPendWrite(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    _In_ PDEVICE_OBJECT FilterDevice,
    _Inout_ PIRP Irp,
    _Out_ PULONGLONG RequestId)
{
    auto *Pending = static_cast<PDISKDRV_PENDING_REQUEST>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DISKDRV_PENDING_REQUEST), 'qDDA'));
    if (Pending == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Pending, sizeof(*Pending));
    Pending->Irp = Irp;
    Pending->FilterDevice = FilterDevice;
    IoMarkIrpPending(Irp);

    KIRQL CancelIrql;
    IoAcquireCancelSpinLock(&CancelIrql);
    if (Irp->Cancel)
    {
        IoReleaseCancelSpinLock(CancelIrql);
        ExFreePoolWithTag(Pending, 'qDDA');
        return STATUS_CANCELLED;
    }

    KIRQL OldIrql;
    KeAcquireSpinLockAtDpcLevel(&Context->Lock);
    Pending->RequestId = ++Context->NextRequestId;
    if (Pending->RequestId == 0)
        Pending->RequestId = ++Context->NextRequestId;
    InsertTailList(&Context->PendingRequests, &Pending->Link);
    Irp->Tail.Overlay.DriverContext[0] = Pending;
    Irp->Tail.Overlay.DriverContext[1] = Context;
    KeReleaseSpinLockFromDpcLevel(&Context->Lock);
    IoSetCancelRoutine(Irp, DiskDrvCancelPendingWrite);
    IoReleaseCancelSpinLock(CancelIrql);
    *RequestId = Pending->RequestId;
    return STATUS_PENDING;
}

static NTSTATUS DiskDrvDecideRequest(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    _In_ const DISKDRV_DECIDE_REQUEST_INPUT *Input)
{
    PDISKDRV_PENDING_REQUEST Found = nullptr;
    KIRQL CancelIrql;
    IoAcquireCancelSpinLock(&CancelIrql);
    KeAcquireSpinLockAtDpcLevel(&Context->Lock);
    for (PLIST_ENTRY Entry = Context->PendingRequests.Flink;
         Entry != &Context->PendingRequests; Entry = Entry->Flink)
    {
        auto *Pending = CONTAINING_RECORD(Entry, DISKDRV_PENDING_REQUEST, Link);
        if (Pending->RequestId == Input->RequestId)
        {
            if (IoSetCancelRoutine(Pending->Irp, nullptr) != nullptr)
            {
                RemoveEntryList(&Pending->Link);
                InitializeListHead(&Pending->Link);
                Found = Pending;
            }
            break;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&Context->Lock);
    IoReleaseCancelSpinLock(CancelIrql);
    if (Found == nullptr)
        return STATUS_NOT_FOUND;

    PIRP Irp = Found->Irp;
    Irp->Tail.Overlay.DriverContext[0] = nullptr;
    Irp->Tail.Overlay.DriverContext[1] = nullptr;
    if (Input->Allow)
    {
        auto *FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(Found->FilterDevice->DeviceExtension);
        IoSkipCurrentIrpStackLocation(Irp);
        IoCallDriver(FilterExt->TargetDevice, Irp);
    }
    else
    {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    ExFreePoolWithTag(Found, 'qDDA');
    return STATUS_SUCCESS;
}

static VOID DiskDrvRejectAllPending(_Inout_ PDISKDRV_DEVICE_EXTENSION Context)
{
    for (;;)
    {
        ULONGLONG RequestId = 0;
        KIRQL OldIrql;
        KeAcquireSpinLock(&Context->Lock, &OldIrql);
        if (!IsListEmpty(&Context->PendingRequests))
            RequestId = CONTAINING_RECORD(Context->PendingRequests.Flink,
                                          DISKDRV_PENDING_REQUEST, Link)->RequestId;
        KeReleaseSpinLock(&Context->Lock, OldIrql);
        if (RequestId == 0)
            break;
        DISKDRV_DECIDE_REQUEST_INPUT Input{};
        Input.RequestId = RequestId;
        Input.Allow = FALSE;
        DiskDrvDecideRequest(Context, &Input);
    }
}

static VOID DiskDrvExpireTokensLocked(_Inout_ PDISKDRV_DEVICE_EXTENSION Context)
{
    const LONGLONG Now = KeQueryInterruptTime();
    for (ULONG Index = 0; Index < kDiskDrvTokenCapacity; ++Index)
    {
        if (Context->Tokens[Index].InUse && Context->Tokens[Index].ExpireTick <= Now)
            Context->Tokens[Index].InUse = FALSE;
    }
}

static VOID DiskDrvQueueEvent(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    ULONG EventType,
    ULONG OperationType,
    ULONG ProcessId,
    ULONGLONG Offset,
    ULONGLONG Length,
    _In_opt_z_ const WCHAR *Detail,
    ULONGLONG RequestId = 0)
{
    DISKDRV_EVENT Event{};
    Event.Version = DISKDRV_PROTOCOL_VERSION;
    Event.EventType = EventType;
    KeQuerySystemTime(&Event.TimeStamp);
    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Event.DiskNumber = Context->DiskNumber;
    Event.PartitionStyle = Context->PartitionStyle;
    KeReleaseSpinLock(&Context->Lock, OldIrql);
    Event.ProcessId = ProcessId;
    Event.ThreadId = HandleToULong(PsGetCurrentThreadId());
    Event.Offset = Offset;
    Event.Length = Length;
    Event.Flags = OperationType;
    Event.RequestId = RequestId;
    if (Detail != nullptr)
        RtlStringCchCopyW(Event.Detail, RTL_NUMBER_OF(Event.Detail), Detail);
    PUNICODE_STRING Image = nullptr;
    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &Image)) && Image != nullptr)
    {
        RtlStringCchCopyNW(Event.ProcessImage, RTL_NUMBER_OF(Event.ProcessImage), Image->Buffer, Image->Length / sizeof(WCHAR));
        ExFreePool(Image);
    }

    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Context->Events[Context->EventWriteIndex] = Event;
    Context->EventWriteIndex = (Context->EventWriteIndex + 1) % kDiskDrvEventCapacity;
    if (Context->EventCount == kDiskDrvEventCapacity)
    {
        Context->EventReadIndex = (Context->EventReadIndex + 1) % kDiskDrvEventCapacity;
    }
    else
    {
        ++Context->EventCount;
    }

    if (OperationType == DiskDrvOperationLayoutIoctl)
        ++Context->BlockedLayoutIoctlCount;
    else
        ++Context->BlockedWriteCount;
    KeReleaseSpinLock(&Context->Lock, OldIrql);
}

static NTSTATUS DiskDrvHandleGetEvent(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    size_t OutputBufferLength,
    _Out_ size_t *BytesReturned)
{
    *BytesReturned = 0;
    if (OutputBufferLength < sizeof(DISKDRV_EVENT))
        return STATUS_BUFFER_TOO_SMALL;

    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    if (Context->EventCount == 0)
    {
        KeReleaseSpinLock(&Context->Lock, OldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    *static_cast<PDISKDRV_EVENT>(OutputBuffer) = Context->Events[Context->EventReadIndex];
    Context->EventReadIndex = (Context->EventReadIndex + 1) % kDiskDrvEventCapacity;
    --Context->EventCount;
    KeReleaseSpinLock(&Context->Lock, OldIrql);
    *BytesReturned = sizeof(DISKDRV_EVENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDrvHandleQueryState(
    _In_ PDISKDRV_DEVICE_EXTENSION Context,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    size_t OutputBufferLength,
    _Out_ size_t *BytesReturned)
{
    *BytesReturned = 0;
    if (OutputBufferLength < sizeof(DISKDRV_STATE_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;

    DISKDRV_STATE_OUTPUT Output{};
    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Output.DiskNumber = Context->DiskNumber;
    Output.PartitionStyle = Context->PartitionStyle;
    Output.Enabled = Context->Enabled;
    Output.AuditOnly = Context->AuditOnly;
    Output.BlockedWriteCount = Context->BlockedWriteCount;
    Output.BlockedLayoutIoctlCount = Context->BlockedLayoutIoctlCount;
    Output.PendingEventCount = Context->EventCount;
    KeReleaseSpinLock(&Context->Lock, OldIrql);

    *static_cast<PDISKDRV_STATE_OUTPUT>(OutputBuffer) = Output;
    *BytesReturned = sizeof(Output);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDrvHandleAllowOnce(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    size_t InputBufferLength)
{
    if (InputBufferLength < sizeof(DISKDRV_ALLOW_ONCE_INPUT))
        return STATUS_BUFFER_TOO_SMALL;

    const auto *Input = static_cast<PDISKDRV_ALLOW_ONCE_INPUT>(InputBuffer);
    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    DiskDrvExpireTokensLocked(Context);
    ULONG Slot = kDiskDrvTokenCapacity;
    for (ULONG Index = 0; Index < kDiskDrvTokenCapacity; ++Index)
    {
        if (!Context->Tokens[Index].InUse)
        {
            Slot = Index;
            break;
        }
    }
    if (Slot == kDiskDrvTokenCapacity)
        Slot = 0;

    Context->Tokens[Slot].InUse = TRUE;
    Context->Tokens[Slot].DiskNumber = Input->DiskNumber;
    Context->Tokens[Slot].OperationType = Input->OperationType;
    Context->Tokens[Slot].ProcessId = Input->ProcessId;
    Context->Tokens[Slot].Offset = Input->Offset;
    Context->Tokens[Slot].Length = Input->Length;
    Context->Tokens[Slot].ExpireTick = KeQueryInterruptTime() + (static_cast<LONGLONG>(Input->TimeoutMs ? Input->TimeoutMs : 5000) * 10000);
    KeReleaseSpinLock(&Context->Lock, OldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDrvHandleClearEvents(_Inout_ PDISKDRV_DEVICE_EXTENSION Context)
{
    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Context->EventReadIndex = 0;
    Context->EventWriteIndex = 0;
    Context->EventCount = 0;
    RtlZeroMemory(Context->Events, sizeof(Context->Events));
    KeReleaseSpinLock(&Context->Lock, OldIrql);
    return STATUS_SUCCESS;
}

static BOOLEAN DiskDrvRangeIntersectsProtected(
    _In_ PDISKDRV_DEVICE_EXTENSION Context,
    _In_ ULONGLONG Offset,
    _In_ ULONG Length)
{
    const ULONG Bps = Context->BytesPerSector != 0 ? Context->BytesPerSector : 512;
    const ULONGLONG WriteStart = Offset;
    const ULONGLONG WriteEnd = Offset + Length - 1;

    const ULONGLONG HeadSectors = (Context->PartitionStyle == PARTITION_STYLE_GPT) ? 34 : 1;
    const ULONGLONG HeadEnd = HeadSectors * Bps - 1;
    if (WriteStart <= HeadEnd)
        return TRUE;

    if (Context->PartitionStyle == PARTITION_STYLE_GPT && Context->DiskBytes >= Bps * 34)
    {
        const ULONGLONG TotalSectors = Context->DiskBytes / Bps;
        const ULONGLONG TailStart = (TotalSectors - 33) * Bps;
        const ULONGLONG TailEnd = TotalSectors * Bps - 1;
        if (WriteStart <= TailEnd && WriteEnd >= TailStart)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN DiskDrvMatchAllowOnceLocked(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    ULONG OperationType,
    ULONGLONG Offset,
    ULONG Length)
{
    const ULONG ProcessId = HandleToULong(PsGetCurrentProcessId());
    const LONGLONG Now = KeQueryInterruptTime();
    for (ULONG Index = 0; Index < kDiskDrvTokenCapacity; ++Index)
    {
        DISKDRV_ALLOW_TOKEN &Token = Context->Tokens[Index];
        if (!Token.InUse)
            continue;
        if (Token.ExpireTick <= Now)
        {
            Token.InUse = FALSE;
            continue;
        }
        if (Token.DiskNumber != Context->DiskNumber)
            continue;
        if (Token.OperationType != OperationType)
            continue;
        if (Token.ProcessId != ProcessId)
            continue;
        if (OperationType == DiskDrvOperationLayoutIoctl)
        {
            Token.InUse = FALSE;
            return TRUE;
        }
        const ULONGLONG TokenStart = Token.Offset;
        const ULONGLONG TokenEnd = Token.Offset + (Token.Length > 0 ? Token.Length - 1 : 0);
        const ULONGLONG WriteStart = Offset;
        const ULONGLONG WriteEnd = Offset + (Length > 0 ? Length - 1 : 0);
        if (WriteStart <= TokenEnd && WriteEnd >= TokenStart)
        {
            Token.InUse = FALSE;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN DiskDrvIsLayoutIoctl(ULONG IoControlCode)
{
    switch (IoControlCode)
    {
    case IOCTL_DISK_CREATE_DISK:
    case IOCTL_DISK_SET_DRIVE_LAYOUT:
    case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
    case IOCTL_DISK_DELETE_DRIVE_LAYOUT:
    case IOCTL_DISK_SET_PARTITION_INFO:
    case IOCTL_DISK_SET_PARTITION_INFO_EX:
    case IOCTL_DISK_GROW_PARTITION:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS DiskDrvSynchronousDeviceIoControl(
	_In_ PDEVICE_OBJECT TargetDevice,
	_In_ ULONG IoControlCode,
	_Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
	size_t OutputBufferLength,
	_Inout_ PIO_STATUS_BLOCK IoStatus)
{
	KEVENT Event;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	PIRP Irp = IoBuildDeviceIoControlRequest(
		IoControlCode,
		TargetDevice,
		nullptr,
		0,
		OutputBuffer,
		static_cast<ULONG>(OutputBufferLength),
		FALSE,
		&Event,
		IoStatus);
	if (Irp == nullptr)
		return STATUS_INSUFFICIENT_RESOURCES;

	IoCallDriver(TargetDevice, Irp);

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10 * 10000000LL; 
	NTSTATUS WaitStatus = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout);
	if (WaitStatus == STATUS_TIMEOUT)
	{
		LogMessage("DiskDrv: IOCTL 0x%08X timed out after 10s, cancelling IRP %p.\n",
		           IoControlCode, (PVOID)Irp);
		IoCancelIrp(Irp);
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
	}

	NTSTATUS Status = IoStatus->Status;
	IoFreeIrp(Irp);
	return Status;
}

static VOID DiskDrvQueryDiskParameters(
    _In_ PDEVICE_OBJECT TargetDevice,
    _Out_ PULONG BytesPerSector,
    _Out_ PULONGLONG DiskBytes)
{
    *BytesPerSector = 512;
    *DiskBytes = 0;

    DISK_GEOMETRY_EX Geometry{};
    IO_STATUS_BLOCK IoStatus{};
    if (NT_SUCCESS(DiskDrvSynchronousDeviceIoControl(
            TargetDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            &Geometry, sizeof(Geometry), &IoStatus)) &&
        Geometry.Geometry.BytesPerSector != 0)
    {
        *BytesPerSector = Geometry.Geometry.BytesPerSector;
    }

    GET_LENGTH_INFORMATION LengthInfo{};
    IoStatus.Status = STATUS_UNSUCCESSFUL;
    if (NT_SUCCESS(DiskDrvSynchronousDeviceIoControl(
            TargetDevice, IOCTL_DISK_GET_LENGTH_INFO,
            &LengthInfo, sizeof(LengthInfo), &IoStatus)))
    {
        *DiskBytes = static_cast<ULONGLONG>(LengthInfo.Length.QuadPart);
    }
}

static VOID DiskDrvDetachFilterLocked(_Inout_ PDISKDRV_DEVICE_EXTENSION Context)
{
    DiskDrvRejectAllPending(Context);
    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    if (!Context->FilterAttached)
    {
        KeReleaseSpinLock(&Context->Lock, OldIrql);
        return;
    }
    Context->Detaching = TRUE;
    Context->FilterAttached = FALSE;
    PDEVICE_OBJECT FilterDevice = Context->FilterDevice;
    KeReleaseSpinLock(&Context->Lock, OldIrql);

    if (FilterDevice != nullptr)
    {

        PDISKDRV_FILTER_EXTENSION FilterExt =
            static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
        PDEVICE_OBJECT LowerDevice = FilterExt->TargetDevice;
        if (LowerDevice != nullptr)
            IoDetachDevice(LowerDevice);
        IoDeleteDevice(FilterDevice);
    }

    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Context->FilterDevice = nullptr;
    Context->Detaching = FALSE;
    KeReleaseSpinLock(&Context->Lock, OldIrql);
}

static VOID DiskDrvDetachFilter(_Inout_ PDISKDRV_DEVICE_EXTENSION Context)
{
    ExAcquireFastMutex(&Context->AttachMutex);
    DiskDrvDetachFilterLocked(Context);
    ExReleaseFastMutex(&Context->AttachMutex);
}

static NTSTATUS DiskDrvEnsureAttached(
    _Inout_ PDISKDRV_DEVICE_EXTENSION Context,
    ULONG DiskNumber)
{
    ExAcquireFastMutex(&Context->AttachMutex);
    NTSTATUS Status = STATUS_SUCCESS;

    KIRQL OldIrql;
    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    const BOOLEAN AlreadyAttached =
        Context->FilterAttached && Context->DiskNumber == DiskNumber && !Context->Detaching;
    KeReleaseSpinLock(&Context->Lock, OldIrql);
    if (AlreadyAttached)
    {
        ExReleaseFastMutex(&Context->AttachMutex);
        return STATUS_SUCCESS;
    }

    DiskDrvDetachFilterLocked(Context);

    WCHAR DevicePath[64];
    RtlStringCchPrintfW(DevicePath, RTL_NUMBER_OF(DevicePath), L"\\Device\\Harddisk%lu\\DR%lu", DiskNumber, DiskNumber);
    UNICODE_STRING TargetName;
    RtlInitUnicodeString(&TargetName, DevicePath);

    PFILE_OBJECT FileObject = nullptr;
    PDEVICE_OBJECT TargetDevice = nullptr;
    Status = IoGetDeviceObjectPointer(&TargetName, FILE_READ_ATTRIBUTES, &FileObject, &TargetDevice);
    if (!NT_SUCCESS(Status))
    {
        ExReleaseFastMutex(&Context->AttachMutex);
        return Status;
    }

    PDEVICE_OBJECT TopDevice = IoGetAttachedDeviceReference(TargetDevice);
    LogMessage("DiskDrv: attach target=%p top=%p\n", (PVOID)TargetDevice, (PVOID)TopDevice);

    ULONG BytesPerSector = 512;
    ULONGLONG DiskBytes = 0;

    PDEVICE_OBJECT FilterDevice = nullptr;
    Status = IoCreateDevice(
        G_DiskDrvDriverObject,
        sizeof(DISKDRV_FILTER_EXTENSION),
        nullptr,
        FILE_DEVICE_DISK,
        0,
        FALSE,
        &FilterDevice);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(TopDevice);
        ObDereferenceObject(FileObject);
        ExReleaseFastMutex(&Context->AttachMutex);
        return Status;
    }

    PDISKDRV_FILTER_EXTENSION FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
    RtlZeroMemory(FilterExt, sizeof(*FilterExt));
    FilterExt->ControlExtension = Context;

    FilterDevice->StackSize = (CCHAR)(TopDevice->StackSize + 1);

    PDEVICE_OBJECT LowerDevice = IoAttachDeviceToDeviceStack(FilterDevice, TopDevice);
    if (LowerDevice == nullptr)
    {
        IoDeleteDevice(FilterDevice);
        ObDereferenceObject(TopDevice);
        ObDereferenceObject(FileObject);
        ExReleaseFastMutex(&Context->AttachMutex);
        return STATUS_NO_SUCH_DEVICE;
    }

    FilterExt->TargetDevice = LowerDevice;
    LogMessage("DiskDrv: filter=%p lower=%p\n", (PVOID)FilterDevice, (PVOID)LowerDevice);

    G_DiskDrvFilterDevice = FilterDevice;
    FilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    ObDereferenceObject(TopDevice);
    ObDereferenceObject(FileObject);

    KeAcquireSpinLock(&Context->Lock, &OldIrql);
    Context->FilterDevice = FilterDevice;
    Context->BytesPerSector = BytesPerSector;
    Context->DiskBytes = DiskBytes;
    Context->DiskNumber = DiskNumber;
    Context->FilterAttached = TRUE;
    Context->Detaching = FALSE;
    KeReleaseSpinLock(&Context->Lock, OldIrql);

    LogMessage("DiskDrv: attached to \\Device\\Harddisk%lu\\DR%lu (bps=%lu, bytes=%llu).\n",
               DiskNumber, DiskNumber, BytesPerSector, DiskBytes);

    ExReleaseFastMutex(&Context->AttachMutex);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDrvControlCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = VerifyRequestorImageSignature(Irp);
    if (NT_SUCCESS(Status) && IoGetCurrentIrpStackLocation(Irp)->FileObject != nullptr)
        IoGetCurrentIrpStackLocation(Irp)->FileObject->FsContext = DISKDRV_AUTHORIZED_FILE_CONTEXT;

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS DiskDrvControlClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->FileObject != nullptr)
        Stack->FileObject->FsContext = nullptr;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDrvControlDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PDISKDRV_DEVICE_EXTENSION Context = static_cast<PDISKDRV_DEVICE_EXTENSION>(DeviceObject->DeviceExtension);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (Stack->FileObject == nullptr ||
        Stack->FileObject->FsContext != DISKDRV_AUTHORIZED_FILE_CONTEXT)
    {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    size_t BytesReturned = 0;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    const size_t InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    const size_t OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (Stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_DISKDRV_GET_EVENT:
        if (OutputBufferLength >= sizeof(DISKDRV_EVENT))
            Status = DiskDrvHandleGetEvent(Context, SystemBuffer, OutputBufferLength, &BytesReturned);
        else
            Status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_DISKDRV_QUERY_STATE:
        if (OutputBufferLength >= sizeof(DISKDRV_STATE_OUTPUT))
            Status = DiskDrvHandleQueryState(Context, SystemBuffer, OutputBufferLength, &BytesReturned);
        else
            Status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_DISKDRV_SET_PROTECTION:
        if (InputBufferLength < sizeof(DISKDRV_SET_PROTECTION_INPUT))
        {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const auto *Input = static_cast<PDISKDRV_SET_PROTECTION_INPUT>(SystemBuffer);
            KIRQL OldIrql;
            KeAcquireSpinLock(&Context->Lock, &OldIrql);
            Context->DiskNumber = Input->DiskNumber;
            Context->PartitionStyle = Input->PartitionStyle;
            Context->Enabled = Input->Enabled ? TRUE : FALSE;
            Context->AuditOnly = Input->AuditOnly ? TRUE : FALSE;
            const ULONG NewDiskNumber = Input->DiskNumber;
            const BOOLEAN NewEnabled = Context->Enabled;
            KeReleaseSpinLock(&Context->Lock, OldIrql);

            if (NewEnabled)
                Status = DiskDrvEnsureAttached(Context, NewDiskNumber);
            else
            {
                DiskDrvDetachFilter(Context);
                Status = STATUS_SUCCESS;
            }
            LogMessage("DiskDrv: SET_PROTECTION disk=%lu style=%lu enabled=%u audit=%u status=0x%08X\n",
                       Input->DiskNumber, Input->PartitionStyle,
                       Input->Enabled ? 1 : 0, Input->AuditOnly ? 1 : 0, Status);
        }
        break;
    case IOCTL_DISKDRV_ALLOW_ONCE:
        if (InputBufferLength >= sizeof(DISKDRV_ALLOW_ONCE_INPUT))
            Status = DiskDrvHandleAllowOnce(Context, SystemBuffer, InputBufferLength);
        else
            Status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_DISKDRV_CLEAR_EVENTS:
        Status = DiskDrvHandleClearEvents(Context);
        break;
    case IOCTL_DISKDRV_DECIDE_REQUEST:
        if (InputBufferLength >= sizeof(DISKDRV_DECIDE_REQUEST_INPUT))
            Status = DiskDrvDecideRequest(
                Context, static_cast<PDISKDRV_DECIDE_REQUEST_INPUT>(SystemBuffer));
        else
            Status = STATUS_BUFFER_TOO_SMALL;
        break;
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS DiskDrvFilterPassThrough(_In_ PDEVICE_OBJECT FilterDevice, _Inout_ PIRP Irp)
{
    PDISKDRV_FILTER_EXTENSION FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FilterExt->TargetDevice, Irp);
}

static NTSTATUS DiskDrvFilterPower(_In_ PDEVICE_OBJECT FilterDevice, _Inout_ PIRP Irp)
{
    PDISKDRV_FILTER_EXTENSION FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(FilterExt->TargetDevice, Irp);
}

static NTSTATUS DiskDrvFilterWrite(_In_ PDEVICE_OBJECT FilterDevice, _Inout_ PIRP Irp)
{
    PDISKDRV_FILTER_EXTENSION FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
    PDISKDRV_DEVICE_EXTENSION Context = FilterExt->ControlExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        goto PassThrough;

    const LONGLONG RawOffset = Stack->Parameters.Write.ByteOffset.QuadPart;
    const ULONG Length = Stack->Parameters.Write.Length;

    BOOLEAN ShouldBlock = FALSE;
    BOOLEAN AuditOnly = FALSE;
    ULONGLONG EventOffset = 0;
    ULONGLONG EventLength = 0;

    if (RawOffset >= 0 && Length > 0)
    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&Context->Lock, &OldIrql);
        const BOOLEAN IsAttached = Context->FilterAttached && !Context->Detaching;
        if (IsAttached && Context->Enabled)
        {
            const ULONGLONG Offset = static_cast<ULONGLONG>(RawOffset);
            if (!DiskDrvMatchAllowOnceLocked(Context, DiskDrvOperationWrite, Offset, Length) &&
                DiskDrvRangeIntersectsProtected(Context, Offset, Length))
            {
                ShouldBlock = TRUE;
                AuditOnly = Context->AuditOnly ? TRUE : FALSE;
                EventOffset = Offset;
                EventLength = Length;
            }
        }
        KeReleaseSpinLock(&Context->Lock, OldIrql);
    }

    if (ShouldBlock && !AuditOnly)
    {
        ULONGLONG RequestId = 0;
        const NTSTATUS PendStatus =
            DiskDrvPendWrite(Context, FilterDevice, Irp, &RequestId);
        if (!NT_SUCCESS(PendStatus))
        {
            Irp->IoStatus.Status = PendStatus;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return PendStatus;
        }
        DiskDrvQueueEvent(Context, DiskDrvEventWriteBlocked, DiskDrvOperationWrite,
                          HandleToULong(PsGetCurrentProcessId()), EventOffset, EventLength,
                          L"Write awaiting user decision (MBR/GPT)", RequestId);
        return STATUS_PENDING;
    }
    if (ShouldBlock && AuditOnly)
    {
        DiskDrvQueueEvent(Context, DiskDrvEventWriteBlocked, DiskDrvOperationWrite,
                          HandleToULong(PsGetCurrentProcessId()), EventOffset, EventLength,
                          L"Audit: write to protected boot region (MBR/GPT)");
    }

    LogMessage("DiskDrv: WRITE irql=%u off=%I64u len=%u attached=%u enabled=%u block=%u\n",
               KeGetCurrentIrql(), RawOffset, Length,
               Context->FilterAttached ? 1 : 0, Context->Enabled ? 1 : 0,
               ShouldBlock ? 1 : 0);

PassThrough:
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FilterExt->TargetDevice, Irp);
}

static NTSTATUS DiskDrvFilterDeviceControl(_In_ PDEVICE_OBJECT FilterDevice, _Inout_ PIRP Irp)
{
    PDISKDRV_FILTER_EXTENSION FilterExt = static_cast<PDISKDRV_FILTER_EXTENSION>(FilterDevice->DeviceExtension);
    PDISKDRV_DEVICE_EXTENSION Context = FilterExt->ControlExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    const ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

    LogMessage("DiskDrv: FILTER-IOCTL code=0x%08X irql=%u attached=%u\n",
               IoControlCode, KeGetCurrentIrql(), FilterExt->ControlExtension->FilterAttached ? 1 : 0);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        goto PassThrough;

    if (DiskDrvIsLayoutIoctl(IoControlCode))
    {
        BOOLEAN ShouldBlock = FALSE;
        BOOLEAN AuditOnly = FALSE;
        KIRQL OldIrql;
        KeAcquireSpinLock(&Context->Lock, &OldIrql);
        const BOOLEAN IsAttached = Context->FilterAttached && !Context->Detaching;
        if (IsAttached && Context->Enabled)
        {
            if (!DiskDrvMatchAllowOnceLocked(Context, DiskDrvOperationLayoutIoctl, 0, 0))
            {
                ShouldBlock = TRUE;
                AuditOnly = Context->AuditOnly ? TRUE : FALSE;
            }
        }
        KeReleaseSpinLock(&Context->Lock, OldIrql);

        if (ShouldBlock && !AuditOnly)
        {
            WCHAR Detail[96];
            RtlStringCchPrintfW(Detail, RTL_NUMBER_OF(Detail),
                                L"Layout-modifying IOCTL 0x%08X blocked", IoControlCode);
            DiskDrvQueueEvent(Context, DiskDrvEventLayoutBlocked, DiskDrvOperationLayoutIoctl,
                              HandleToULong(PsGetCurrentProcessId()), 0, 0, Detail);
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
        if (ShouldBlock && AuditOnly)
        {
            WCHAR Detail[96];
            RtlStringCchPrintfW(Detail, RTL_NUMBER_OF(Detail),
                                L"Audit: layout IOCTL 0x%08X", IoControlCode);
            DiskDrvQueueEvent(Context, DiskDrvEventLayoutBlocked, DiskDrvOperationLayoutIoctl,
                              HandleToULong(PsGetCurrentProcessId()), 0, 0, Detail);
        }
    }

PassThrough:
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FilterExt->TargetDevice, Irp);
}

static NTSTATUS DiskDrvInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    G_DiskDrvDriverObject = DriverObject;

    UNICODE_STRING DeviceName;
    UNICODE_STRING SymLink;
    RtlInitUnicodeString(&DeviceName, L"\\Device\\DiskDrv");
    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\DiskDrv");

    PDEVICE_OBJECT Device = nullptr;
    NTSTATUS Status = IoCreateDevice(
        DriverObject,
        sizeof(DISKDRV_DEVICE_EXTENSION),
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &Device);
    if (!NT_SUCCESS(Status))
        return Status;

    Device->Flags |= DO_BUFFERED_IO;
    Device->Flags &= ~DO_DEVICE_INITIALIZING;
    G_DiskDrvControlDevice = Device;

    PDISKDRV_DEVICE_EXTENSION Context =
        static_cast<PDISKDRV_DEVICE_EXTENSION>(Device->DeviceExtension);
    RtlZeroMemory(Context, sizeof(*Context));
    KeInitializeSpinLock(&Context->Lock);
    ExInitializeFastMutex(&Context->AttachMutex);
    InitializeListHead(&Context->PendingRequests);
    Context->NextRequestId = 0;
    Context->ControlDevice = Device;
    Context->Enabled = TRUE;
    Context->DiskNumber = 0;
    Context->PartitionStyle = PARTITION_STYLE_MBR;

    Status = IoCreateSymbolicLink(&SymLink, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(Device);
        G_DiskDrvControlDevice = nullptr;
        return Status;
    }

    DiskDrvQueueEvent(Context, DiskDrvEventLayoutBlocked, DiskDrvOperationLayoutIoctl,
                      4, 0, 0, L"DiskDrv initialized. Boot-region write protection ready.");

    LogMessage("DiskDrv subsystem initialized.\n");
    return STATUS_SUCCESS;
}

static VOID DiskDrvUninitialize(VOID)
{
    if (G_DiskDrvControlDevice != nullptr)
    {
        PDISKDRV_DEVICE_EXTENSION Context =
            static_cast<PDISKDRV_DEVICE_EXTENSION>(G_DiskDrvControlDevice->DeviceExtension);
        DiskDrvDetachFilter(Context);

        UNICODE_STRING SymLink;
        RtlInitUnicodeString(&SymLink, L"\\DosDevices\\DiskDrv");
        IoDeleteSymbolicLink(&SymLink);

        IoDeleteDevice(G_DiskDrvControlDevice);
        G_DiskDrvControlDevice = nullptr;
        G_DiskDrvFilterDevice = nullptr;
        LogMessage("DiskDrv subsystem unloaded.\n");
    }
}
