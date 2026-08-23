namespace Callbacks {
    static PVOID ProcessRegHandle = nullptr;
    static PVOID ThreadRegHandle = nullptr;
    static PVOID ImageRegHandle = nullptr;

    static VOID NTAPI ProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
        (void)Process;
        MonitorEvent Evt = {};
        if (CreateInfo) {
            Evt.Type = EventProcessCreate;
            Evt.ProcessId = HandleToULong(ProcessId);
            Evt.ParentPid = HandleToULong(CreateInfo->ParentProcessId);
            if (CreateInfo->ImageFileName) {
                RtlStringCbCopyNW(Evt.Path, sizeof(Evt.Path), CreateInfo->ImageFileName->Buffer,
                    CreateInfo->ImageFileName->Length);
            }
            if (CreateInfo->CommandLine) {
                RtlStringCbCopyNW(Evt.Extra, sizeof(Evt.Extra), CreateInfo->CommandLine->Buffer,
                    CreateInfo->CommandLine->Length);
            }
        }
        else {
            Evt.Type = EventProcessExit;
            Evt.ProcessId = HandleToULong(ProcessId);
        }
        CommPushSystemEvent(&Evt);
    }

    static VOID NTAPI LegacyProcessNotify(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
        (void)ParentId;
        MonitorEvent Evt = {};
        Evt.Type = Create ? EventProcessCreate : EventProcessExit;
        Evt.ProcessId = HandleToULong(ProcessId);
        RtlStringCbCopyW(Evt.Path, sizeof(Evt.Path),
            Create ? L"ProcessCreate" : L"ProcessExit");
        CommPushSystemEvent(&Evt);
    }

    static VOID NTAPI ThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
        MonitorEvent Evt = {};
        Evt.ProcessId = HandleToULong(ProcessId);
        Evt.ThreadId = HandleToULong(ThreadId);
        if (Create) {
            Evt.Type = EventThreadCreate;
        }
        else {
            Evt.Type = EventThreadExit;
        }
        CommPushSystemEvent(&Evt);
    }

    static VOID NTAPI ImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
        MonitorEvent Evt = {};
        Evt.Type = HandleToULong(ProcessId) == 0 ? EventDriverLoad : EventImageLoad;
        Evt.ProcessId = HandleToULong(ProcessId);
        const ULONG64 ImageBase = static_cast<ULONG64>(reinterpret_cast<ULONG_PTR>(ImageInfo->ImageBase));
        Evt.Data1 = static_cast<ULONG>(ImageBase);
        Evt.Data2 = static_cast<ULONG>(ImageBase >> 32);
        if (FullImageName && FullImageName->Buffer) {
            RtlStringCbCopyNW(Evt.Path, sizeof(Evt.Path), FullImageName->Buffer, FullImageName->Length);
        }
        CommPushSystemEvent(&Evt);
    }

    static void RegisterProcess() {
        NTSTATUS S = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
        if (NT_SUCCESS(S)) {
            ProcessRegHandle = reinterpret_cast<PVOID>(1);
            DRV_INFO("Process callback registered");
            return;
        }

        DRV_WARN("Process callback ex registration failed: 0x%08X, falling back to legacy API", S);
        S = PsSetCreateProcessNotifyRoutine(LegacyProcessNotify, FALSE);
        if (NT_SUCCESS(S)) {
            ProcessRegHandle = reinterpret_cast<PVOID>(2);
            DRV_INFO("Legacy process callback registered");
        }
        else {
            DRV_ERROR("Process callback failed: 0x%08X", S);
        }
    }

    static void UnregisterProcess() {
        if (ProcessRegHandle == reinterpret_cast<PVOID>(1)) {
            PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        }
        else if (ProcessRegHandle == reinterpret_cast<PVOID>(2)) {
            PsSetCreateProcessNotifyRoutine(LegacyProcessNotify, TRUE);
        }
        if (ProcessRegHandle) {
            ProcessRegHandle = nullptr;
            DRV_INFO("Process callback unregistered");
        }
    }

    static void RegisterThread() {
        NTSTATUS S = PsSetCreateThreadNotifyRoutine(ThreadNotify);
        if (NT_SUCCESS(S)) { ThreadRegHandle = reinterpret_cast<PVOID>(1); DRV_INFO("Thread callback registered"); }
        else { DRV_ERROR("Thread callback failed: 0x%08X", S); }
    }

    static void UnregisterThread() {
        if (ThreadRegHandle) { PsRemoveCreateThreadNotifyRoutine(ThreadNotify); ThreadRegHandle = nullptr; DRV_INFO("Thread callback unregistered"); }
    }

    static void RegisterImage() {
        NTSTATUS S = PsSetLoadImageNotifyRoutine(ImageNotify);
        if (NT_SUCCESS(S)) { ImageRegHandle = reinterpret_cast<PVOID>(1); DRV_INFO("Image load callback registered"); }
        else { DRV_ERROR("Image load callback failed: 0x%08X", S); }
    }

    static void UnregisterImage() {
        if (ImageRegHandle) { PsRemoveLoadImageNotifyRoutine(ImageNotify); ImageRegHandle = nullptr; DRV_INFO("Image load callback unregistered"); }
    }
}
