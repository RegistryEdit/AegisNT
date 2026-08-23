
static MonitorRuleV3 G_Rules[MONITOR_MAX_RULES] = {};
static KSPIN_LOCK G_RulesLock;
static ULONG G_NextRuleId = 1;

static BOOLEAN RulesPrefixMatch(PCWSTR Prefix, PCWSTR Value) {
    if (Prefix == nullptr || Prefix[0] == L'\0') return TRUE;
    if (Value == nullptr) return FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(G_Rules[0].Target); ++i) {
        if (Prefix[i] == L'\0') return TRUE;
        if (Value[i] == L'\0' || RtlUpcaseUnicodeChar(Prefix[i]) != RtlUpcaseUnicodeChar(Value[i])) return FALSE;
    }
    return FALSE;
}

VOID RulesInitialize() { KeInitializeSpinLock(&G_RulesLock); }

NTSTATUS RulesOperate(const MonitorRuleOperationV3* Input) {
    if (Input == nullptr || Input->Size < sizeof(*Input) || Input->Version != MONITOR_PROTOCOL_VERSION) return STATUS_INVALID_PARAMETER;
    KIRQL irql; KeAcquireSpinLock(&G_RulesLock, &irql);
    NTSTATUS status = STATUS_SUCCESS;
    if (Input->Operation == MonitorRuleClear) {
        RtlZeroMemory(G_Rules, sizeof(G_Rules));
    } else if (Input->Operation == MonitorRuleRemove) {
        ULONG i; for (i = 0; i < MONITOR_MAX_RULES && G_Rules[i].Id != Input->Rule.Id; ++i) {}
        if (i == MONITOR_MAX_RULES) status = STATUS_NOT_FOUND; else RtlZeroMemory(&G_Rules[i], sizeof(G_Rules[i]));
    } else if (Input->Operation == MonitorRuleAdd &&
               Input->Rule.Type >= MonitorRuleFile && Input->Rule.Type <= MonitorRuleNetwork &&
               Input->Rule.Action >= MonitorRuleAudit && Input->Rule.Action <= MonitorRuleBlock) {
        ULONG i; for (i = 0; i < MONITOR_MAX_RULES && G_Rules[i].Id != 0; ++i) {}
        if (i == MONITOR_MAX_RULES) status = STATUS_INSUFFICIENT_RESOURCES;
        else { G_Rules[i] = Input->Rule; G_Rules[i].Id = G_NextRuleId++; G_Rules[i].HitCount = 0; G_Rules[i].Target[259] = L'\0'; }
    } else status = STATUS_INVALID_PARAMETER;
    KeReleaseSpinLock(&G_RulesLock, irql); return status;
}

VOID RulesEnumerate(MonitorRuleListV3* Output) {
    RtlZeroMemory(Output, sizeof(*Output)); Output->Size = sizeof(*Output); Output->Version = MONITOR_PROTOCOL_VERSION;
    KIRQL irql; KeAcquireSpinLock(&G_RulesLock, &irql);
    for (ULONG i = 0; i < MONITOR_MAX_RULES; ++i) if (G_Rules[i].Id) Output->Rules[Output->Count++] = G_Rules[i];
    KeReleaseSpinLock(&G_RulesLock, irql);
}

MonitorRuleAction RulesEvaluate(MonitorRuleType Type, ULONG ProcessId, PCWSTR Target, ULONG Protocol, ULONG RemotePort, PULONG RuleId) {
    MonitorRuleAction result = MonitorRuleAudit; if (RuleId) *RuleId = 0;
    KIRQL irql; KeAcquireSpinLock(&G_RulesLock, &irql);
    for (ULONG i = 0; i < MONITOR_MAX_RULES; ++i) { MonitorRuleV3* r = &G_Rules[i];
        if (!r->Id || r->Type != Type || (r->ProcessId && r->ProcessId != ProcessId) ||
            (Type == MonitorRuleNetwork && ((r->Protocol && r->Protocol != Protocol) || (r->RemotePort && r->RemotePort != RemotePort))) ||
            !RulesPrefixMatch(r->Target, Target)) continue;
        ++r->HitCount; result = static_cast<MonitorRuleAction>(r->Action); if (RuleId) *RuleId = r->Id; break;
    }
    KeReleaseSpinLock(&G_RulesLock, irql); return result;
}
