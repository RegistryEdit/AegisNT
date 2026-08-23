namespace ObMon {
    static PVOID ObRegHandle = nullptr;

    static OB_PREOP_CALLBACK_STATUS NTAPI PreOpCallback(PVOID Ctx, POB_PRE_OPERATION_INFORMATION Info) {
        (void)Ctx;
        MonitorEvent Evt = {};
        Evt.Type = EventHandleOperation;
        Evt.ProcessId = HandleToULong(PsGetCurrentProcessId());
        Evt.ThreadId = HandleToULong(PsGetCurrentThreadId());
        if (Info->ObjectType == *PsProcessType) {
            RtlStringCbCopyW(Evt.Path, sizeof(Evt.Path), L"ProcessHandle");
            Evt.ParentPid = HandleToULong(PsGetProcessId(reinterpret_cast<PEPROCESS>(Info->Object)));
        }
        else if (Info->ObjectType == *PsThreadType) {
            RtlStringCbCopyW(Evt.Path, sizeof(Evt.Path), L"ThreadHandle");
            Evt.ParentPid = HandleToULong(PsGetThreadId(reinterpret_cast<PETHREAD>(Info->Object)));
        }
        else                                         RtlStringCbCopyW(Evt.Path, sizeof(Evt.Path), L"OtherHandle");
        Evt.Data1 = Info->Operation;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Evt.Data2 = static_cast<ULONG>(Info->Parameters->CreateHandleInformation.DesiredAccess);
        }
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            Evt.Data2 = static_cast<ULONG>(Info->Parameters->DuplicateHandleInformation.DesiredAccess);
        }
        CommPushSystemEvent(&Evt);

        if (Info->ObjectType == *PsProcessType &&
            Info->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            ACCESS_MASK Access = Info->Parameters->CreateHandleInformation.DesiredAccess;
            if ((Access & 0x0020) && (Access & 0x0002))  
            {
                MonitorEvent InjEvt = {};
                InjEvt.Type = EventProcessInject;
                InjEvt.ProcessId = HandleToULong(PsGetCurrentProcessId());
                InjEvt.ParentPid = HandleToULong(PsGetProcessId(reinterpret_cast<PEPROCESS>(Info->Object)));
                InjEvt.Data1 = static_cast<ULONG>(Access);
                RtlStringCbPrintfW(InjEvt.Path, sizeof(InjEvt.Path),
                    L"Injection: VM_WRITE|CREATE_THREAD on PID %u", InjEvt.ParentPid);
                KeQuerySystemTime(&InjEvt.TimeStamp);
                CommPushSystemEvent(&InjEvt);
            }
        }

        return OB_PREOP_SUCCESS;
    }

    static NTSTATUS Register(PDRIVER_OBJECT DriverObject) {
        (void)DriverObject;
        OB_OPERATION_REGISTRATION Ops[2] = {};
        OB_CALLBACK_REGISTRATION Reg = {};
        Reg.Version = OB_FLT_REGISTRATION_VERSION;
        Reg.OperationRegistrationCount = 2;
        Reg.OperationRegistration = Ops;
        Reg.RegistrationContext = nullptr;
        RtlInitUnicodeString(&Reg.Altitude, OB_CALLBACK_ALTITUDE);
        Ops[0].ObjectType = PsProcessType;
        Ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        Ops[0].PreOperation = PreOpCallback;
        Ops[0].PostOperation = nullptr;
        Ops[1].ObjectType = PsThreadType;
        Ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        Ops[1].PreOperation = PreOpCallback;
        Ops[1].PostOperation = nullptr;
        NTSTATUS S = ObRegisterCallbacks(&Reg, &ObRegHandle);
        if (NT_SUCCESS(S)) {
            DRV_INFO("Object Callback Registered");
        }
        else if (S == STATUS_ACCESS_DENIED) {
            DRV_ERROR("Object Callback Failed: 0x%08X (requires a validly signed callback image)", S);
        }
        else {
            DRV_ERROR("Object Callback Failed: 0x%08X", S);
        }
        return S;
    }

    static void Unregister() {
        if (ObRegHandle) { ObUnRegisterCallbacks(ObRegHandle); ObRegHandle = nullptr; DRV_INFO("Object Callback Unregistered"); }
    }
}
