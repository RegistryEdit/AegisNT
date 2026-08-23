namespace NetworkMon {
    static HANDLE Engine = nullptr;
    static UINT32 RuntimeCalloutIds[4] = {};
    static const GUID CalloutKeys[4] = {
        {0xa35c4e91,0x8e77,0x47d1,{0x9c,0xa2,0x71,0x3e,0x44,0xe8,0x11,0x20}},
        {0xa35c4e92,0x8e77,0x47d1,{0x9c,0xa2,0x71,0x3e,0x44,0xe8,0x11,0x20}},
        {0xa35c4e93,0x8e77,0x47d1,{0x9c,0xa2,0x71,0x3e,0x44,0xe8,0x11,0x20}},
        {0xa35c4e94,0x8e77,0x47d1,{0x9c,0xa2,0x71,0x3e,0x44,0xe8,0x11,0x20}}
    };

    static VOID NTAPI Classify(const FWPS_INCOMING_VALUES0* Values,
        const FWPS_INCOMING_METADATA_VALUES0* Metadata, VOID*,
        const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0* ClassifyOut) {
        if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) return;
        MonitorEvent Event = {};
        Event.Type = Values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ||
            Values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6 ? EventNetworkAccept : EventNetworkConnect;
        if (Metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)
            Event.ProcessId = (ULONG)Metadata->processId;
        UINT16 LocalPort = 0, RemotePort = 0; UINT8 Protocol = 0;
        switch (Values->layerId) {
        case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
            Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16; break;
        case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
            Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
            LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
            RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16; break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
            Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
            LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
            RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16; break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
            Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
            LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
            RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16; break;
        }
        Event.Data1 = Protocol;
        Event.Data2 = (static_cast<ULONG>(LocalPort) << 16) | RemotePort;
        const BOOLEAN IsIpv6 = Values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6 ||
            Values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

        if (Event.Type == EventNetworkConnect && RemotePort == 53)
            Event.Type = EventDnsQuery;

        if (Event.Type == EventNetworkConnect && (RemotePort == 80 || RemotePort == 443 || RemotePort == 8080))
            Event.Type = EventHttpRequest;

        // WFP classify can run at DISPATCH_LEVEL. Keep this path free of
        // printf-style Unicode helpers, which inspect process state and can
        // touch pageable memory at elevated IRQL.
        CommCopyResidentString(Event.Path, RTL_NUMBER_OF(Event.Path),
            IsIpv6 ? L"IPv6" : L"IPv4");
        CommCopyResidentString(Event.Extra, RTL_NUMBER_OF(Event.Extra),
            Event.Type == EventNetworkAccept ? L"Inbound network event"
            : Event.Type == EventHttpRequest ? L"HTTP-like network event"
            : L"Outbound network event");

        ULONG RuleId = 0;
        const MonitorRuleAction RuleAction = RulesEvaluate(MonitorRuleNetwork, Event.ProcessId, nullptr, Protocol, RemotePort, &RuleId);
        if (RuleAction == MonitorRuleBlock) {
            CommCopyResidentString(Event.Extra, RTL_NUMBER_OF(Event.Extra),
                L"Blocked by network rule");
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        KeQuerySystemTime(&Event.TimeStamp);
        if (CommEventAllowed(&Event)) { QueuePushEvent(&G_NetworkQueue, &Event); QueuePushEvent(&G_SystemQueue, &Event); }
        if (RuleAction != MonitorRuleBlock) ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER0*) { return STATUS_SUCCESS; }

    static NTSTATUS AddFilter(const GUID* LayerKey, const GUID* CalloutKey) {
        FWPM_CALLOUT0 Callout = {};
        Callout.calloutKey = *CalloutKey; Callout.displayData.name = const_cast<wchar_t*>(L"AegisSentinel ALE metadata");
        Callout.applicableLayer = *LayerKey;
        NTSTATUS Status = FwpmCalloutAdd0(Engine, &Callout, nullptr, nullptr);
        if (!NT_SUCCESS(Status)) return Status;
        FWPM_FILTER0 Filter = {};
        Filter.displayData.name = const_cast<wchar_t*>(L"AegisSentinel ALE metadata");
        Filter.layerKey = *LayerKey; Filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
        Filter.action.type = FWP_ACTION_CALLOUT_INSPECTION; Filter.action.calloutKey = *CalloutKey;
        Filter.weight.type = FWP_EMPTY;
        return FwpmFilterAdd0(Engine, &Filter, nullptr, nullptr);
    }

    static NTSTATUS Register(PDEVICE_OBJECT DeviceObject) {
        NTSTATUS Status = STATUS_SUCCESS;
        FWPM_SESSION0 Session = {}; Session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        Session.displayData.name = const_cast<wchar_t*>(L"AegisSentinel dynamic session");
        for (ULONG Index = 0; Index < RTL_NUMBER_OF(CalloutKeys); ++Index) {
            FWPS_CALLOUT0 Runtime = {}; Runtime.calloutKey = CalloutKeys[Index]; Runtime.classifyFn = Classify; Runtime.notifyFn = Notify;
            Status = FwpsCalloutRegister0(DeviceObject, &Runtime, &RuntimeCalloutIds[Index]); if (!NT_SUCCESS(Status)) goto Failure;
        }
        Status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &Session, &Engine); if (!NT_SUCCESS(Status)) goto Failure;
        Status = FwpmTransactionBegin0(Engine, 0); if (!NT_SUCCESS(Status)) goto Failure;
        Status = AddFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &CalloutKeys[0]);
        if (NT_SUCCESS(Status)) Status = AddFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V6, &CalloutKeys[1]);
        if (NT_SUCCESS(Status)) Status = AddFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &CalloutKeys[2]);
        if (NT_SUCCESS(Status)) Status = AddFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &CalloutKeys[3]);
        if (NT_SUCCESS(Status)) Status = FwpmTransactionCommit0(Engine); else FwpmTransactionAbort0(Engine);
        if (NT_SUCCESS(Status)) { DRV_INFO("WFP ALE metadata monitor registered"); return STATUS_SUCCESS; }
Failure:
        if (Engine) { FwpmEngineClose0(Engine); Engine = nullptr; }
        for (ULONG Index = 0; Index < RTL_NUMBER_OF(RuntimeCalloutIds); ++Index)
            if (RuntimeCalloutIds[Index]) { FwpsCalloutUnregisterById0(RuntimeCalloutIds[Index]); RuntimeCalloutIds[Index] = 0; }
        return Status;
    }

    static VOID Unregister() {
        if (Engine) { FwpmEngineClose0(Engine); Engine = nullptr; }
        for (ULONG Index = 0; Index < RTL_NUMBER_OF(RuntimeCalloutIds); ++Index)
            if (RuntimeCalloutIds[Index]) { FwpsCalloutUnregisterById0(RuntimeCalloutIds[Index]); RuntimeCalloutIds[Index] = 0; }
    }
}
