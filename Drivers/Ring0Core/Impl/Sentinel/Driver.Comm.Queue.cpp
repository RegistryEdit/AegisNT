static VOID QueueInitialize(_Out_ PMONITOR_EVENT_QUEUE Queue) {
    RtlZeroMemory(Queue, sizeof(*Queue));
    KeInitializeSpinLock(&Queue->Lock);
    KeInitializeEvent(&Queue->Available, NotificationEvent, FALSE);
}

static NTSTATUS QueueAllocateBuffer(_Inout_ PMONITOR_EVENT_QUEUE Queue) {
    Queue->Buffer = reinterpret_cast<MonitorEvent*>(
        ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MonitorEvent) * MAX_EVENTS, SENTINEL_TAG));
    if (Queue->Buffer == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Queue->Buffer, sizeof(MonitorEvent) * MAX_EVENTS);
    return STATUS_SUCCESS;
}

static VOID QueueCleanup(_Inout_ PMONITOR_EVENT_QUEUE Queue) {
    if (Queue->Buffer != nullptr) {
        ExFreePoolWithTag(Queue->Buffer, SENTINEL_TAG);
        Queue->Buffer = nullptr;
    }
    Queue->ReadIndex = 0;
    Queue->WriteIndex = 0;
    Queue->Count = 0;
    Queue->HighWatermark = 0;
    Queue->Dropped = 0;
}

static VOID QueueClear(_Inout_ PMONITOR_EVENT_QUEUE Queue) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&Queue->Lock, &OldIrql);
    Queue->ReadIndex = 0;
    Queue->WriteIndex = 0;
    Queue->Count = 0;
    KeClearEvent(&Queue->Available);
    KeReleaseSpinLock(&Queue->Lock, OldIrql);
}

static NTSTATUS QueuePopEvent(
    _Inout_ PMONITOR_EVENT_QUEUE Queue,
    _Out_ MonitorEvent* Event
) {
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;

    KIRQL OldIrql;
    KeAcquireSpinLock(&Queue->Lock, &OldIrql);
    if (Queue->Count > 0) {
        *Event = Queue->Buffer[Queue->ReadIndex];
        Queue->ReadIndex = (Queue->ReadIndex + 1) % MAX_EVENTS;
        Queue->Count--;
        Status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Queue->Lock, OldIrql);

    return Status;
}

static NTSTATUS QueuePushEvent(
    _Inout_ PMONITOR_EVENT_QUEUE Queue,
    _In_ const MonitorEvent* Event
) {
    if (Queue->Buffer == nullptr) {
        return STATUS_UNSUCCESSFUL;
    }

    KIRQL OldIrql;
    KeAcquireSpinLock(&Queue->Lock, &OldIrql);
    if (Queue->Count >= MAX_EVENTS) {
        Queue->ReadIndex = (Queue->ReadIndex + 1) % MAX_EVENTS;
        Queue->Count--;
        Queue->Dropped++;
    }

    Queue->Buffer[Queue->WriteIndex] = *Event;
    Queue->WriteIndex = (Queue->WriteIndex + 1) % MAX_EVENTS;
    Queue->Count++;
    if (Queue->Count > Queue->HighWatermark) Queue->HighWatermark = Queue->Count;
    KeSetEvent(&Queue->Available, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&Queue->Lock, OldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS CommInitialize(PDRIVER_OBJECT DriverObject) {
    QueueInitialize(&G_SystemQueue);
    QueueInitialize(&G_FileQueue);
    QueueInitialize(&G_NetworkQueue);
    ExInitializeFastMutex(&G_WatchLock);
    KeInitializeSpinLock(&G_FilterLock);
    RulesInitialize();

    NTSTATUS Status = QueueAllocateBuffer(&G_SystemQueue);
    if (!NT_SUCCESS(Status)) {
        DRV_ERROR("System event buffer allocation failed");
        return Status;
    }

    Status = QueueAllocateBuffer(&G_FileQueue);
    if (!NT_SUCCESS(Status)) {
        DRV_ERROR("File event buffer allocation failed");
        QueueCleanup(&G_SystemQueue);
        return Status;
    }

    Status = QueueAllocateBuffer(&G_NetworkQueue);
    if (!NT_SUCCESS(Status)) {
        DRV_ERROR("Network event buffer allocation failed");
        QueueCleanup(&G_FileQueue);
        QueueCleanup(&G_SystemQueue);
        return Status;
    }

    UNICODE_STRING DevName, DosName;
    RtlInitUnicodeString(&DevName, AEGISSENTINEL_DEVICE_NAME);
    RtlInitUnicodeString(&DosName, AEGISSENTINEL_DOS_DEVICE_NAME);

    Status = IoCreateDevice(DriverObject, 0, &DevName,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &G_SentinelDeviceObject);
    if (!NT_SUCCESS(Status)) {
        DRV_ERROR("IoCreateDevice Failed: 0x%08X", Status);
        QueueCleanup(&G_FileQueue);
        QueueCleanup(&G_NetworkQueue);
        QueueCleanup(&G_SystemQueue);
        return Status;
    }

    Status = IoCreateSymbolicLink(&DosName, &DevName);
    if (!NT_SUCCESS(Status)) {
        DRV_ERROR("IoCreateSymbolicLink Failed: 0x%08X", Status);
        IoDeleteDevice(G_SentinelDeviceObject);
        G_SentinelDeviceObject = nullptr;
        QueueCleanup(&G_FileQueue);
        QueueCleanup(&G_NetworkQueue);
        QueueCleanup(&G_SystemQueue);
        return Status;
    }

    G_SentinelDeviceObject->Flags |= DO_BUFFERED_IO;
    G_SentinelDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DRV_INFO("Device Object Created");
    return STATUS_SUCCESS;
}

static void CommCleanup() {
    UNICODE_STRING DosName;
    RtlInitUnicodeString(&DosName, AEGISSENTINEL_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&DosName);
    if (G_SentinelDeviceObject) { IoDeleteDevice(G_SentinelDeviceObject); G_SentinelDeviceObject = nullptr; }
    QueueCleanup(&G_FileQueue);
    QueueCleanup(&G_NetworkQueue);
    QueueCleanup(&G_SystemQueue);
    DRV_INFO("Device Object Destroyed");
}

static VOID CommCopyResidentString(PWCHAR Destination, SIZE_T Capacity, PCWSTR Source) {
    if (Destination == nullptr || Capacity == 0) return;
    SIZE_T Index = 0;
    if (Source != nullptr) {
        while (Index + 1 < Capacity && Source[Index] != L'\0') {
            Destination[Index] = Source[Index];
            ++Index;
        }
    }
    Destination[Index] = L'\0';
}

static WCHAR CommFoldAsciiPathChar(WCHAR Character) {
    return Character >= L'a' && Character <= L'z' ? Character - (L'a' - L'A') : Character;
}

static BOOLEAN CommPathHasPrefixResident(PCWSTR Prefix, PCWSTR Path) {
    for (ULONG Index = 0; Index < 260; ++Index) {
        const WCHAR PrefixCharacter = Prefix[Index];
        if (PrefixCharacter == L'\0') return TRUE;
        const WCHAR PathCharacter = Path[Index];
        if (PathCharacter == L'\0' ||
            CommFoldAsciiPathChar(PrefixCharacter) != CommFoldAsciiPathChar(PathCharacter)) return FALSE;
    }
    return TRUE;
}

static BOOLEAN CommEventAllowed(const MonitorEvent* Event) {
    MonitorFilterV2 Filter = {};
    KIRQL OldIrql;
    KeAcquireSpinLock(&G_FilterLock, &OldIrql);
    Filter = G_MonitorFilter;
    KeReleaseSpinLock(&G_FilterLock, OldIrql);
    if (Event->Type < 64 && (Filter.EventMask & (1ull << Event->Type)) == 0) return FALSE;
    if (Filter.ProcessId != 0 && Event->ProcessId != Filter.ProcessId) return FALSE;
    if (Filter.PathPrefix[0] != L'\0') {
        if (!CommPathHasPrefixResident(Filter.PathPrefix, Event->Path)) return FALSE;
    }
    return TRUE;
}

static NTSTATUS CommPushSystemEvent(MonitorEvent* Event) {
    if (!CommEventAllowed(Event)) return STATUS_SUCCESS;
    KeQuerySystemTime(&Event->TimeStamp);
    return QueuePushEvent(&G_SystemQueue, Event);
}

static NTSTATUS CommPushFileEvent(MonitorEvent* Event) {
    KeQuerySystemTime(&Event->TimeStamp);
    if (!CommEventAllowed(Event)) return STATUS_SUCCESS;
    QueuePushEvent(&G_SystemQueue, Event);
    return QueuePushEvent(&G_FileQueue, Event);
}

static VOID ConvertEventV2(const MonitorEvent* Source, MonitorEventV2* Destination) {
    RtlZeroMemory(Destination, sizeof(*Destination));
    Destination->Size = sizeof(*Destination);
    Destination->Version = MONITOR_PROTOCOL_VERSION;
    Destination->Type = Source->Type;
    Destination->Sequence = (ULONG64)InterlockedIncrement64(&G_EventSequence);
    Destination->TimeStamp = Source->TimeStamp;
    Destination->Status = STATUS_SUCCESS;
    Destination->ProcessId = Source->ProcessId;
    Destination->ThreadId = Source->ThreadId;
    Destination->ParentPid = Source->ParentPid;
    Destination->Operation = Source->Data1;
    Destination->Value1 = Source->Data1;
    Destination->Value2 = Source->Data2;
    if (Source->Type == EventNetworkConnect || Source->Type == EventNetworkAccept) {
        Destination->Operation = Source->Data1;
        Destination->Value1 = (Source->Data2 >> 16) & 0xFFFFu;
        Destination->Value2 = Source->Data2 & 0xFFFFu;
    }
    if (Source->Type == EventImageLoad || Source->Type == EventDriverLoad || Source->Type == EventDriverUnload) Destination->Address =
        static_cast<ULONG64>(Source->Data1) | (static_cast<ULONG64>(Source->Data2) << 32);
    if (Source->Type == EventHandleOperation) {
        if (Source->Path[0] == L'P') Destination->TargetProcessId = Source->ParentPid;
        else Destination->TargetThreadId = Source->ParentPid;
    }
    if (Source->Type == EventFileOperation) Destination->SizeBytes = Source->Data2;
    if (Source->Type == EventRegistryOperation) {
        Destination->DataType = Source->ParentPid;
        Destination->SizeBytes = Source->Data2;
        MonitorFilterV2 Filter = {};
        KIRQL OldIrql;
        KeAcquireSpinLock(&G_FilterLock, &OldIrql); Filter = G_MonitorFilter; KeReleaseSpinLock(&G_FilterLock, OldIrql);
        if ((Filter.Flags & MONITOR_FILTER_REGISTRY_PREVIEW) && Filter.RegistryPreviewBytes < Source->Data2)
            Destination->Flags |= MONITOR_EVENT_FLAG_TRUNCATED;
        Destination->ParentPid = 0;
    }
    RtlStringCchCopyW(Destination->Path, RTL_NUMBER_OF(Destination->Path), Source->Path);
    RtlStringCchCopyW(Destination->Extra, RTL_NUMBER_OF(Destination->Extra), Source->Extra);
}
