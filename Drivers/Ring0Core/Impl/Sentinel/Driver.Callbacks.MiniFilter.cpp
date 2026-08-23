namespace MiniFilter {
    static PFLT_FILTER G_Filter = nullptr;

    static BOOLEAN CopyWatchDirectorySnapshot(
        _Out_writes_(260) PWCHAR DirectoryPath,
        _Out_opt_ PBOOLEAN Active
    ) {
        BOOLEAN IsActive = FALSE;

        ExAcquireFastMutex(&G_WatchLock);
        IsActive = G_WatchDirectoryActive;
        if (IsActive) {
            RtlStringCchCopyW(DirectoryPath, 260, G_WatchedDirectory);
        }
        ExReleaseFastMutex(&G_WatchLock);

        if (!IsActive && DirectoryPath != nullptr) {
            DirectoryPath[0] = L'\0';
        }
        if (Active != nullptr) {
            *Active = IsActive;
        }
        return IsActive;
    }

    static BOOLEAN IsPathSeparator(_In_ WCHAR Ch) {
        return Ch == L'\\' || Ch == L'/';
    }

    static BOOLEAN EqualsInsensitivePrefix(
        _In_reads_(Length) PCWSTR Left,
        _In_reads_(Length) PCWSTR Right,
        _In_ SIZE_T Length
    ) {
        for (SIZE_T Index = 0; Index < Length; ++Index)
        {
            if (RtlUpcaseUnicodeChar(Left[Index]) != RtlUpcaseUnicodeChar(Right[Index]))
                return FALSE;
        }
        return TRUE;
    }

    static BOOLEAN IsWatchedPath(_In_ PCWSTR Path) {
        WCHAR WatchDirectory[260] = {};
        SIZE_T WatchLength = 0;

        if (Path == nullptr || Path[0] == L'\0') {
            return FALSE;
        }
        if (!CopyWatchDirectorySnapshot(WatchDirectory, nullptr)) {
            return FALSE;
        }
        if (!NT_SUCCESS(RtlStringCchLengthW(WatchDirectory, RTL_NUMBER_OF(WatchDirectory), &WatchLength)) ||
            WatchLength == 0) {
            return FALSE;
        }
        if (!EqualsInsensitivePrefix(Path, WatchDirectory, WatchLength)) {
            return FALSE;
        }

        return Path[WatchLength] == L'\0' || IsPathSeparator(Path[WatchLength]);
    }

    static BOOLEAN GetProcessName(
        _In_ PEPROCESS Process,
        _Out_writes_(260) PWCHAR Buffer
    ) {
        BOOLEAN Success = FALSE;
        UNICODE_STRING RoutineName;
        RtlInitUnicodeString(&RoutineName, L"SeLocateProcessImageName");
        auto LocateProcessImageName =
            reinterpret_cast<PSE_LOCATE_PROCESS_IMAGE_NAME>(MmGetSystemRoutineAddress(&RoutineName));
        if (LocateProcessImageName == nullptr) {
            return FALSE;
        }

        PUNICODE_STRING ImagePath = nullptr;
        if (NT_SUCCESS(LocateProcessImageName(Process, &ImagePath)) &&
            ImagePath != nullptr &&
            ImagePath->Buffer != nullptr) {
            Success = NT_SUCCESS(RtlStringCbCopyNW(Buffer, sizeof(WCHAR) * 260,
                ImagePath->Buffer, ImagePath->Length));
        }

        if (ImagePath != nullptr) {
            ExFreePool(ImagePath);
        }
        return Success;
    }

    static VOID FillFileEvent(
        _Inout_ MonitorEvent* Event,
        _In_ PCUNICODE_STRING FilePath,
        _In_ PCWSTR Operation,
        _In_ ULONG Data1,
        _In_ ULONG Data2
    ) {
        RtlZeroMemory(Event, sizeof(*Event));
        Event->Type = EventFileOperation;
        Event->ProcessId = HandleToULong(PsGetCurrentProcessId());
        Event->ThreadId = HandleToULong(PsGetCurrentThreadId());
        Event->Data1 = Data1;
        Event->Data2 = Data2;

        if (FilePath != nullptr && FilePath->Buffer != nullptr && FilePath->Length != 0) {
            RtlStringCbCopyNW(Event->Path, sizeof(Event->Path), FilePath->Buffer, FilePath->Length);
        }

        if (Operation != nullptr) {
            RtlStringCchCopyW(Event->Extra, RTL_NUMBER_OF(Event->Extra), Operation);
            WCHAR ProcessPath[260] = {};
            if (GetProcessName(PsGetCurrentProcess(), ProcessPath)) {
                SIZE_T Used = 0;
                if (NT_SUCCESS(RtlStringCchLengthW(Event->Extra, RTL_NUMBER_OF(Event->Extra), &Used)) &&
                    Used + 4 < RTL_NUMBER_OF(Event->Extra)) {
                    RtlStringCchCatW(Event->Extra, RTL_NUMBER_OF(Event->Extra), L" | ");
                    RtlStringCchCatW(Event->Extra, RTL_NUMBER_OF(Event->Extra), ProcessPath);
                }
            }
        }
    }

    static VOID PublishFileEvent(
        _In_ PFLT_CALLBACK_DATA Data,
        _In_ PCWSTR Operation
    ) {
        if (!WatchDirectoryConfigured()) {
            return;
        }

        PFLT_FILE_NAME_INFORMATION NameInfo = nullptr;
        NTSTATUS Status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);
        if (!NT_SUCCESS(Status) || NameInfo == nullptr) {
            return;
        }

        Status = FltParseFileNameInformation(NameInfo);
        WCHAR FilePath[260] = {};
        if (NT_SUCCESS(Status) &&
            NameInfo->Name.Buffer != nullptr &&
            NameInfo->Name.Length != 0 &&
            NT_SUCCESS(RtlStringCbCopyNW(FilePath, sizeof(FilePath),
                NameInfo->Name.Buffer, NameInfo->Name.Length)) &&
            IsWatchedPath(FilePath)) {
            MonitorEvent Event = {};
            UNICODE_STRING FilePathString;
            RtlInitUnicodeString(&FilePathString, FilePath);
            FillFileEvent(&Event, &FilePathString, Operation,
                Data->Iopb->MajorFunction, Data->Iopb->MinorFunction);
            if (Data->Iopb->MajorFunction == IRP_MJ_READ)
                Event.Data2 = Data->Iopb->Parameters.Read.Length;
            else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
                Event.Data2 = Data->Iopb->Parameters.Write.Length;
            CommPushFileEvent(&Event);
        }

        FltReleaseFileNameInformation(NameInfo);
    }

    static BOOLEAN ShouldBlockFile(_In_ PFLT_CALLBACK_DATA Data, _Out_ PULONG RuleId) {
        PFLT_FILE_NAME_INFORMATION NameInfo = nullptr;
        if (!NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo)) || NameInfo == nullptr) return FALSE;
        BOOLEAN Block = FALSE;
        if (NT_SUCCESS(FltParseFileNameInformation(NameInfo))) {
            WCHAR Path[260] = {};
            if (NameInfo->Name.Buffer && NT_SUCCESS(RtlStringCbCopyNW(Path, sizeof(Path), NameInfo->Name.Buffer, NameInfo->Name.Length)))
                Block = RulesEvaluate(MonitorRuleFile, HandleToULong(PsGetCurrentProcessId()), Path, 0, 0, RuleId) == MonitorRuleBlock;
        }
        FltReleaseFileNameInformation(NameInfo);
        return Block;
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI PreCreate(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);
        PublishFileEvent(Data, L"Create/Open");

        {
            PFLT_FILE_NAME_INFORMATION NameInfo = nullptr;
            if (NT_SUCCESS(FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo)) && NameInfo)
            {
                if (NT_SUCCESS(FltParseFileNameInformation(NameInfo)) &&
                    NameInfo->Name.Buffer != nullptr &&
                    wcsstr(NameInfo->Name.Buffer, L"NamedPipe") != NULL)
                {
                    MonitorEvent PipeEvt = {};
                    PipeEvt.Type = EventNamedPipeConnect;
                    PipeEvt.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                    if (NameInfo->Name.Length < sizeof(PipeEvt.Path) - sizeof(WCHAR))
                        RtlCopyMemory(PipeEvt.Path, NameInfo->Name.Buffer, NameInfo->Name.Length);
                    RtlStringCbCopyW(PipeEvt.Extra, sizeof(PipeEvt.Extra), L"Named pipe connection");
                    KeQuerySystemTime(&PipeEvt.TimeStamp);
                    if (CommEventAllowed(&PipeEvt))
                        CommPushSystemEvent(&PipeEvt);
                }
                FltReleaseFileNameInformation(NameInfo);
            }
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI PreWrite(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);
        PublishFileEvent(Data, L"Write");

        if (WatchDirectoryConfigured())
        {
            PFLT_FILE_NAME_INFORMATION CapInfo = nullptr;
            if (NT_SUCCESS(FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &CapInfo)) && CapInfo)
            {
                if (NT_SUCCESS(FltParseFileNameInformation(CapInfo)))
                {
                    WCHAR CheckPath[260];
                    if (CapInfo->Name.Buffer && CapInfo->Name.Length < sizeof(CheckPath) - sizeof(WCHAR))
                    {
                        RtlStringCbCopyNW(CheckPath, sizeof(CheckPath),
                            CapInfo->Name.Buffer, CapInfo->Name.Length);
                        if (IsWatchedPath(CheckPath))
                        {
                            MonitorEvent Evt = {};
                            Evt.Type = EventFileCapture;
                            Evt.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                            Evt.Data1 = Data->Iopb->Parameters.Write.Length;
                            Evt.Data2 = (ULONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
                            if (CapInfo->Name.Length < sizeof(Evt.Path) - sizeof(WCHAR))
                                RtlCopyMemory(Evt.Path, CapInfo->Name.Buffer, CapInfo->Name.Length);
                            KeQuerySystemTime(&Evt.TimeStamp);
                            if (CommEventAllowed(&Evt))
                                CommPushFileEvent(&Evt);
                        }
                    }
                }
                FltReleaseFileNameInformation(CapInfo);
            }
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI PreSetInformation(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);
        PublishFileEvent(Data, L"SetInformation");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI MergedPreCreate(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        ULONG RuleId = 0;
        if (ShouldBlockFile(Data, &RuleId)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DRV_WARN("File rule %lu blocked create", RuleId);
            return FLT_PREOP_COMPLETE;
        }
        FLT_PREOP_CALLBACK_STATUS CoreStatus = PreCreateCallback(Data, FltObjects, CompletionContext);
        if (CoreStatus != FLT_PREOP_SUCCESS_NO_CALLBACK) {
            return CoreStatus;
        }
        return PreCreate(Data, FltObjects, CompletionContext);
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI MergedPreWrite(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        ULONG RuleId = 0;
        if (ShouldBlockFile(Data, &RuleId)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DRV_WARN("File rule %lu blocked write", RuleId);
            return FLT_PREOP_COMPLETE;
        }
        FLT_PREOP_CALLBACK_STATUS CoreStatus = PreWriteCallback(Data, FltObjects, CompletionContext);
        if (CoreStatus != FLT_PREOP_SUCCESS_NO_CALLBACK) {
            return CoreStatus;
        }
        return PreWrite(Data, FltObjects, CompletionContext);
    }

    static FLT_PREOP_CALLBACK_STATUS NTAPI MergedPreSetInformation(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext
    ) {
        FLT_PREOP_CALLBACK_STATUS CoreStatus = PreSetInformationCallback(Data, FltObjects, CompletionContext);
        if (CoreStatus != FLT_PREOP_SUCCESS_NO_CALLBACK) {
            return CoreStatus;
        }
        return PreSetInformation(Data, FltObjects, CompletionContext);
    }

    static const FLT_OPERATION_REGISTRATION OpCallbacks[] = {
        { IRP_MJ_CREATE,           0, MergedPreCreate, nullptr },
        { IRP_MJ_READ,             0, nullptr, nullptr },
        { IRP_MJ_WRITE,            0, MergedPreWrite, nullptr },
        { IRP_MJ_SET_INFORMATION,  0, MergedPreSetInformation, nullptr },
        { IRP_MJ_DIRECTORY_CONTROL, 0, nullptr, nullptr },
        { IRP_MJ_CLEANUP,          0, nullptr, nullptr },
        { IRP_MJ_CLOSE,            0, nullptr, nullptr },
        { IRP_MJ_OPERATION_END }
    };

    static VOID PublishVolumeEvent(PCFLT_RELATED_OBJECTS FltObjects, MonitorEventType Type) {
        MonitorEvent Event = {}; Event.Type = Type; Event.ProcessId = HandleToULong(PsGetCurrentProcessId());
        Event.ThreadId = HandleToULong(PsGetCurrentThreadId());
        if (FltObjects && FltObjects->Volume) {
            ULONG Required = 0;
            UNICODE_STRING VolumeName = { 0, static_cast<USHORT>(sizeof(Event.Path) - sizeof(WCHAR)), Event.Path };
            FltGetVolumeName(FltObjects->Volume, &VolumeName, &Required);
            Event.Path[min((ULONG)(VolumeName.Length / sizeof(WCHAR)), (ULONG)RTL_NUMBER_OF(Event.Path) - 1)] = L'\0';
        }
        RtlStringCchCopyW(Event.Extra, RTL_NUMBER_OF(Event.Extra), Type == EventVolumeMount ? L"InstanceSetup" : L"InstanceTeardown");
        CommPushSystemEvent(&Event);
    }

    static NTSTATUS NTAPI InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS,
        DEVICE_TYPE, FLT_FILESYSTEM_TYPE) {
        PublishVolumeEvent(FltObjects, EventVolumeMount); return STATUS_SUCCESS;
    }

    static VOID NTAPI InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS) {
        PublishVolumeEvent(FltObjects, EventVolumeDismount);
    }

    static NTSTATUS NTAPI FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
        UNREFERENCED_PARAMETER(Flags);
        DRV_INFO("Minifilter unload allowed by FilterUnload callback");
        return STATUS_SUCCESS;
    }

    static const FLT_REGISTRATION FilterReg = {
        sizeof(FLT_REGISTRATION),
        FLT_REGISTRATION_VERSION,
        0, nullptr,
        OpCallbacks,
        FilterUnload, InstanceSetup, nullptr, nullptr, InstanceTeardownComplete,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    };

    static NTSTATUS Register(PDRIVER_OBJECT DriverObject) {
        NTSTATUS S = FltRegisterFilter(DriverObject, &FilterReg, &G_Filter);
        if (!NT_SUCCESS(S)) { DRV_ERROR("FltRegisterFilter Failed: 0x%08X", S); return S; }
        S = FltStartFiltering(G_Filter);
        if (!NT_SUCCESS(S)) {
            DRV_ERROR("FltStartFiltering Failed: 0x%08X", S);
            FltUnregisterFilter(G_Filter); G_Filter = nullptr;
            return S;
        }
        DRV_INFO("Minifilter Registered And Started");
        return STATUS_SUCCESS;
    }

    static void Unregister() {
        if (G_Filter) { FltUnregisterFilter(G_Filter); G_Filter = nullptr; DRV_INFO("Minifilter Unregistered"); }
    }
}
