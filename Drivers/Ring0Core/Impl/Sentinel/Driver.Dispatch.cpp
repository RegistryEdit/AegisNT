static NTSTATUS IrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = VerifyRequestorImageSignature(Irp);
    if (NT_SUCCESS(Status)) {
        Stack->FileObject->FsContext = MON_AUTHORIZED_FILE_CONTEXT;
    }
    else {
        DRV_WARN("Denied device open, status 0x%08X", Status);
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS IrpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->FileObject != NULL) Stack->FileObject->FsContext = NULL;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR Info = 0;

    if (Stack->FileObject == NULL ||
        Stack->FileObject->FsContext != MON_AUTHORIZED_FILE_CONTEXT) {
        Status = STATUS_ACCESS_DENIED;
        goto CompleteRequest;
    }

    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_MONITOR_GET_EVENT: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorEvent)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MonitorEvent Evt = {};
        Status = QueuePopEvent(&G_SystemQueue, &Evt);
        if (Status == STATUS_SUCCESS) {
            Info = sizeof(MonitorEvent);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Evt, sizeof(MonitorEvent));
        }
        break;
    }
    case IOCTL_MONITOR_GET_FILE_EVENT: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorEvent)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MonitorEvent Evt = {};
        Status = QueuePopEvent(&G_FileQueue, &Evt);
        if (Status == STATUS_SUCCESS) {
            Info = sizeof(MonitorEvent);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Evt, sizeof(MonitorEvent));
        }
        break;
    }
    case IOCTL_MONITOR_SET_WATCH_DIRECTORY: {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MonitorWatchDirectoryInput)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* Input = reinterpret_cast<MonitorWatchDirectoryInput*>(Irp->AssociatedIrp.SystemBuffer);
        Input->DirectoryPath[RTL_NUMBER_OF(Input->DirectoryPath) - 1] = L'\0';
        Status = SetWatchDirectory(Input->DirectoryPath);
        break;
    }
    case IOCTL_MONITOR_CLEAR_WATCH_DIRECTORY:
        ClearWatchDirectory();
        Status = STATUS_SUCCESS;
        break;
    case IOCTL_MONITOR_QUERY_WATCH_DIRECTORY: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorWatchDirectoryOutput)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* Output = reinterpret_cast<MonitorWatchDirectoryOutput*>(Irp->AssociatedIrp.SystemBuffer);
        QueryWatchDirectory(Output);
        Status = STATUS_SUCCESS;
        Info = sizeof(MonitorWatchDirectoryOutput);
        break;
    }
    case IOCTL_MONITOR_GET_EVENT_V2:
    case IOCTL_MONITOR_GET_NETWORK_EVENT_V2: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorEventV2)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MonitorEvent Legacy = {};
        PMONITOR_EVENT_QUEUE Queue = Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MONITOR_GET_NETWORK_EVENT_V2
            ? &G_NetworkQueue : &G_SystemQueue;
        Status = QueuePopEvent(Queue, &Legacy);
        if (NT_SUCCESS(Status)) {
            MonitorEventV2 Event = {};
            ConvertEventV2(&Legacy, &Event);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Event, sizeof(Event));
            Info = sizeof(Event);
        }
        break;
    }
    case IOCTL_MONITOR_SET_FILTER_V2: {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MonitorFilterV2)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto Input = reinterpret_cast<MonitorFilterV2*>(Irp->AssociatedIrp.SystemBuffer);
        if (Input->Size < sizeof(*Input) || Input->Version != MONITOR_PROTOCOL_VERSION || Input->RegistryPreviewBytes > 512) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        Input->PathPrefix[RTL_NUMBER_OF(Input->PathPrefix) - 1] = L'\0';
        KIRQL OldIrql;
        KeAcquireSpinLock(&G_FilterLock, &OldIrql);
        G_MonitorFilter = *Input;
        KeReleaseSpinLock(&G_FilterLock, OldIrql);
        Status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_MONITOR_QUERY_STATS_V2: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorStatsV2)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        MonitorStatsV2 Stats = {};
        Stats.Size = sizeof(Stats); Stats.Version = MONITOR_PROTOCOL_VERSION;
        KIRQL OldIrql;
        KeAcquireSpinLock(&G_SystemQueue.Lock, &OldIrql); Stats.SystemQueued = G_SystemQueue.Count; Stats.SystemHighWatermark = G_SystemQueue.HighWatermark; Stats.SystemDropped = G_SystemQueue.Dropped; KeReleaseSpinLock(&G_SystemQueue.Lock, OldIrql);
        KeAcquireSpinLock(&G_FileQueue.Lock, &OldIrql); Stats.FileQueued = G_FileQueue.Count; Stats.FileHighWatermark = G_FileQueue.HighWatermark; Stats.FileDropped = G_FileQueue.Dropped; KeReleaseSpinLock(&G_FileQueue.Lock, OldIrql);
        KeAcquireSpinLock(&G_NetworkQueue.Lock, &OldIrql); Stats.NetworkQueued = G_NetworkQueue.Count; Stats.NetworkHighWatermark = G_NetworkQueue.HighWatermark; Stats.NetworkDropped = G_NetworkQueue.Dropped; KeReleaseSpinLock(&G_NetworkQueue.Lock, OldIrql);
        Stats.LastSequence = (ULONG64)G_EventSequence;
        Stats.QueueCapacity = MAX_EVENTS;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Stats, sizeof(Stats));
        Info = sizeof(Stats); Status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_MONITOR_RULE_OPERATION_V3: {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MonitorRuleOperationV3)) { Status = STATUS_BUFFER_TOO_SMALL; break; }
        Status = RulesOperate(reinterpret_cast<MonitorRuleOperationV3*>(Irp->AssociatedIrp.SystemBuffer));
        break;
    }
    case IOCTL_MONITOR_ENUM_RULES_V3: {
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MonitorRuleListV3)) { Status = STATUS_BUFFER_TOO_SMALL; break; }
        RulesEnumerate(reinterpret_cast<MonitorRuleListV3*>(Irp->AssociatedIrp.SystemBuffer));
        Info = sizeof(MonitorRuleListV3); Status = STATUS_SUCCESS;
        break;
    }
    default:
        break;
    }
CompleteRequest:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
