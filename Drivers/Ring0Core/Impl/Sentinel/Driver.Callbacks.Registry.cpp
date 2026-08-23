namespace RegistryMon {
    static LARGE_INTEGER CmCookie = {};

    static const WCHAR* OpToString(REG_NOTIFY_CLASS NotifyClass) {
        switch (NotifyClass) {
        case RegNtPreCreateKeyEx:       return L"CreateKey";
        case RegNtPreOpenKeyEx:         return L"OpenKey";
        case RegNtDeleteKey:            return L"DeleteKey";
        case RegNtDeleteValueKey:       return L"DeleteValue";
        case RegNtSetValueKey:          return L"SetValue";
        case RegNtQueryKey:             return L"QueryKey";
        case RegNtQueryValueKey:        return L"QueryValue";
        case RegNtEnumerateKey:         return L"EnumKey";
        case RegNtEnumerateValueKey:    return L"EnumValue";
        case RegNtQueryMultipleValueKey: return L"QueryMultiValue";
        case RegNtRenameKey:            return L"RenameKey";
        case RegNtKeyHandleClose:       return L"CloseKey";
        default: return L"Unknown";
        }
    }

    static NTSTATUS NTAPI RegistryCallback(PVOID Ctx, PVOID Arg1, PVOID Arg2) {
        (void)Ctx;
        REG_NOTIFY_CLASS Nc = static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(Arg1));
        MonitorEvent Evt = {};
        Evt.Type = EventRegistryOperation;
        Evt.ProcessId = HandleToULong(PsGetCurrentProcessId());
        Evt.ThreadId = HandleToULong(PsGetCurrentThreadId());
        Evt.Data1 = static_cast<ULONG>(Nc);
        PVOID KeyObject = nullptr;
        PUNICODE_STRING ValueName = nullptr;
        if ((Nc == RegNtPreCreateKeyEx || Nc == RegNtPreOpenKeyEx) && Arg2 != nullptr) {
            auto Info = reinterpret_cast<PREG_CREATE_KEY_INFORMATION>(Arg2);
            if (Info->CompleteName) RtlStringCbCopyNW(Evt.Path, sizeof(Evt.Path), Info->CompleteName->Buffer, Info->CompleteName->Length);
            KeyObject = Info->RootObject;
        }
        else if (Nc == RegNtPreSetValueKey && Arg2 != nullptr) {
            auto Info = reinterpret_cast<PREG_SET_VALUE_KEY_INFORMATION>(Arg2);
            KeyObject = Info->Object; ValueName = Info->ValueName; Evt.Data2 = Info->DataSize; Evt.ParentPid = Info->Type;
            WCHAR ValueText[128] = {};
            if (ValueName && ValueName->Buffer)
                RtlStringCbCopyNW(ValueText, sizeof(ValueText), ValueName->Buffer, ValueName->Length);
            RtlStringCchPrintfW(Evt.Extra, RTL_NUMBER_OF(Evt.Extra), L"%ws | Type %lu | Size %lu",
                ValueText, Info->Type, Info->DataSize);
            MonitorFilterV2 Filter = {};
            KIRQL OldIrql;
            KeAcquireSpinLock(&G_FilterLock, &OldIrql); Filter = G_MonitorFilter; KeReleaseSpinLock(&G_FilterLock, OldIrql);
            if ((Filter.Flags & MONITOR_FILTER_REGISTRY_PREVIEW) && Filter.RegistryPreviewBytes != 0 && Info->Data != nullptr &&
                (Info->Type == REG_SZ || Info->Type == REG_EXPAND_SZ || Info->Type == REG_MULTI_SZ)) {
                ULONG PreviewBytes = min(min(Filter.RegistryPreviewBytes, Info->DataSize), 256ul * sizeof(WCHAR));
                PreviewBytes &= ~1ul;
                __try {
                    WCHAR Preview[257] = {};
                    RtlCopyMemory(Preview, Info->Data, PreviewBytes); Preview[PreviewBytes / sizeof(WCHAR)] = L'\0';
                    RtlStringCchCatW(Evt.Extra, RTL_NUMBER_OF(Evt.Extra), L" | Data ");
                    RtlStringCchCatW(Evt.Extra, RTL_NUMBER_OF(Evt.Extra), Preview);
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
        }
        else if (Nc == RegNtPreDeleteValueKey && Arg2 != nullptr) {
            auto Info = reinterpret_cast<PREG_DELETE_VALUE_KEY_INFORMATION>(Arg2);
            KeyObject = Info->Object; ValueName = Info->ValueName;
            if (ValueName) RtlStringCbCopyNW(Evt.Extra, sizeof(Evt.Extra), ValueName->Buffer, ValueName->Length);
        }
        else if (Nc == RegNtPreQueryValueKey && Arg2 != nullptr) {
            auto Info = reinterpret_cast<PREG_QUERY_VALUE_KEY_INFORMATION>(Arg2);
            KeyObject = Info->Object; ValueName = Info->ValueName;
            if (ValueName) RtlStringCbCopyNW(Evt.Extra, sizeof(Evt.Extra), ValueName->Buffer, ValueName->Length);
        }
        else if ((Nc == RegNtPreDeleteKey || Nc == RegNtPreQueryKey || Nc == RegNtPreEnumerateKey) && Arg2 != nullptr) {
            KeyObject = *reinterpret_cast<PVOID*>(Arg2);
        }
        PCUNICODE_STRING KeyName = nullptr;
        if (KeyObject != nullptr && NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&CmCookie, KeyObject, nullptr, &KeyName, 0)) && KeyName != nullptr) {
            RtlStringCbCopyNW(Evt.Path, sizeof(Evt.Path), KeyName->Buffer, KeyName->Length);
            CmCallbackReleaseKeyObjectIDEx(KeyName);
        }
        if (Evt.Path[0] == L'\0') RtlStringCbCopyW(Evt.Path, sizeof(Evt.Path), OpToString(Nc));
        if (Evt.Extra[0] == L'\0') RtlStringCbCopyW(Evt.Extra, sizeof(Evt.Extra), OpToString(Nc));
        CommPushSystemEvent(&Evt);

        ULONG RuleId = 0;
        if (RulesEvaluate(MonitorRuleRegistry, Evt.ProcessId, Evt.Path, 0, 0, &RuleId) == MonitorRuleBlock) {
            DRV_WARN("Registry rule %lu blocked %ws", RuleId, Evt.Path);
            return STATUS_ACCESS_DENIED;
        }

        if (Nc == RegNtPreSetValueKey && Evt.Path[0] != L'\0' &&
            ValueName != nullptr && ValueName->Buffer != nullptr &&
            wcsstr(Evt.Path, L"\\Services\\") != NULL)
        {
            if (_wcsnicmp(ValueName->Buffer, L"Start", 5) == 0)
            {
                MonitorEvent SvcEvt = {};
                SvcEvt.Type = EventServiceStateChange;
                SvcEvt.ProcessId = Evt.ProcessId;
                SvcEvt.Data1 = Evt.ParentPid;
                RtlStringCbCopyW(SvcEvt.Path, sizeof(SvcEvt.Path), Evt.Path);
                RtlStringCbPrintfW(SvcEvt.Extra, sizeof(SvcEvt.Extra), L"Service Start state changed");
                KeQuerySystemTime(&SvcEvt.TimeStamp);
                CommPushSystemEvent(&SvcEvt);
            }
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS Register(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject) return STATUS_INVALID_PARAMETER;
        UNICODE_STRING Alt;
        RtlInitUnicodeString(&Alt, CM_CALLBACK_ALTITUDE);
        DRV_INFO("Registering registry callback");
        NTSTATUS S = CmRegisterCallbackEx(RegistryCallback, &Alt, DriverObject, nullptr, &CmCookie, nullptr);
        if (NT_SUCCESS(S)) { DRV_INFO("Registry Callback Registered"); }
        else { DRV_ERROR("Registry Callback Failed: 0x%08X", S); }
        return S;
    }

    static void Unregister() {
        if (CmCookie.QuadPart != 0) { CmUnRegisterCallback(CmCookie); CmCookie.QuadPart = 0; DRV_INFO("Registry Callback Unregistered"); }
    }
}
