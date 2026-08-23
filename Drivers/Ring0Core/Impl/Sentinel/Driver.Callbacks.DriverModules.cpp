namespace DriverModuleMon {
    typedef struct _MODULE_ENTRY {
        HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags;
        USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];
    } MODULE_ENTRY;
    typedef struct _MODULE_INFO { ULONG Count; MODULE_ENTRY Modules[1]; } MODULE_INFO;
    typedef struct _SNAPSHOT_ENTRY { ULONG_PTR Base; WCHAR Path[260]; } SNAPSHOT_ENTRY;

    static KEVENT StopEvent;
    static HANDLE ThreadHandle = nullptr;
    static SNAPSHOT_ENTRY* Previous = nullptr;
    static ULONG PreviousCount = 0;

    static NTSTATUS Capture(SNAPSHOT_ENTRY** Entries, PULONG Count) {
        *Entries = nullptr; *Count = 0; ULONG Required = 0;
        typedef NTSTATUS (NTAPI* PZW_QUERY_SYSTEM_INFORMATION)(ULONG, PVOID, ULONG, PULONG);
        UNICODE_STRING RoutineName;
        RtlInitUnicodeString(&RoutineName, L"ZwQuerySystemInformation");
        auto QuerySystemInformation = reinterpret_cast<PZW_QUERY_SYSTEM_INFORMATION>(MmGetSystemRoutineAddress(&RoutineName));
        if (!QuerySystemInformation) return STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS Status = QuerySystemInformation(11, nullptr, 0, &Required);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) return Status;
        auto Buffer = static_cast<MODULE_INFO*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, Required, SENTINEL_TAG));
        if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;
        Status = QuerySystemInformation(11, Buffer, Required, &Required);
        if (!NT_SUCCESS(Status)) { ExFreePoolWithTag(Buffer, SENTINEL_TAG); return Status; }
        ULONG Number = min(Buffer->Count, 2048ul);
        auto Snapshot = static_cast<SNAPSHOT_ENTRY*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SNAPSHOT_ENTRY) * Number, SENTINEL_TAG));
        if (!Snapshot) { ExFreePoolWithTag(Buffer, SENTINEL_TAG); return STATUS_INSUFFICIENT_RESOURCES; }
        RtlZeroMemory(Snapshot, sizeof(SNAPSHOT_ENTRY) * Number);
        for (ULONG Index = 0; Index < Number; ++Index) {
            Snapshot[Index].Base = reinterpret_cast<ULONG_PTR>(Buffer->Modules[Index].ImageBase);
            for (ULONG Char = 0; Char + 1 < RTL_NUMBER_OF(Snapshot[Index].Path) && Buffer->Modules[Index].FullPathName[Char]; ++Char)
                Snapshot[Index].Path[Char] = static_cast<WCHAR>(Buffer->Modules[Index].FullPathName[Char]);
        }
        ExFreePoolWithTag(Buffer, SENTINEL_TAG); *Entries = Snapshot; *Count = Number; return STATUS_SUCCESS;
    }

    static BOOLEAN Contains(SNAPSHOT_ENTRY* Entries, ULONG Count, ULONG_PTR Base) {
        for (ULONG Index = 0; Index < Count; ++Index) if (Entries[Index].Base == Base) return TRUE;
        return FALSE;
    }

    static VOID NTAPI Worker(PVOID) {
        LARGE_INTEGER Interval; Interval.QuadPart = -20ll * 1000 * 1000;
        while (KeWaitForSingleObject(&StopEvent, Executive, KernelMode, FALSE, &Interval) == STATUS_TIMEOUT) {
            SNAPSHOT_ENTRY* Current = nullptr; ULONG CurrentCount = 0;
            if (!NT_SUCCESS(Capture(&Current, &CurrentCount))) continue;
            if (Previous != nullptr) {
                for (ULONG Index = 0; Index < PreviousCount; ++Index) {
                    if (Contains(Current, CurrentCount, Previous[Index].Base)) continue;
                    MonitorEvent Event = {}; Event.Type = EventDriverUnload;
                    Event.Data1 = static_cast<ULONG>(Previous[Index].Base);
                    Event.Data2 = static_cast<ULONG>(Previous[Index].Base >> 32);
                    RtlStringCchCopyW(Event.Path, RTL_NUMBER_OF(Event.Path), Previous[Index].Path);
                    RtlStringCchCopyW(Event.Extra, RTL_NUMBER_OF(Event.Extra), L"Module snapshot diff");
                    CommPushSystemEvent(&Event);
                }
                ExFreePoolWithTag(Previous, SENTINEL_TAG);
            }
            Previous = Current; PreviousCount = CurrentCount;
        }
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    static NTSTATUS Register() {
        KeInitializeEvent(&StopEvent, NotificationEvent, FALSE);
        Capture(&Previous, &PreviousCount);
        return PsCreateSystemThread(&ThreadHandle, SYNCHRONIZE, nullptr, nullptr, nullptr, Worker, nullptr);
    }

    static VOID Unregister() {
        KeSetEvent(&StopEvent, IO_NO_INCREMENT, FALSE);
        if (ThreadHandle) { ZwWaitForSingleObject(ThreadHandle, FALSE, nullptr); ZwClose(ThreadHandle); ThreadHandle = nullptr; }
        if (Previous) { ExFreePoolWithTag(Previous, SENTINEL_TAG); Previous = nullptr; PreviousCount = 0; }
    }
}
