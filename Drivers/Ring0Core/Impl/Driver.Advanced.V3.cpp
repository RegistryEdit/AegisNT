struct ADVANCED_TRANSACTION_SLOT {
    BOOLEAN Active;
    ULONG Kind;
    ULONG TargetId;
    ULONG64 Id;
    ULONG_PTR Address;
    ULONG64 Before;
    ULONG64 After;
};
typedef ADVANCED_TRANSACTION_SLOT* PADVANCED_TRANSACTION_SLOT;

static ADVANCED_TRANSACTION_SLOT G_AdvancedTransactions[32] = {};
static KSPIN_LOCK G_AdvancedTransactionLock;
static volatile LONG64 G_AdvancedTransactionId = 0;

static VOID AdvancedInitRecord(PMDV2_RECORD Record, ULONG Kind, PCWSTR Name,
                               NTSTATUS Status = STATUS_SUCCESS) {
    Mdv2InitRecord(Record, Kind, Mdv2SourceKernelStructure);
    Record->Status = Status;
    if (Name) RtlStringCchCopyW(Record->Name, RTL_NUMBER_OF(Record->Name), Name);
}

static NTSTATUS AdvancedQuery(const MDV2_QUERY_INPUT* Query,
                              PMDV2_LIST_OUTPUT Output, ULONG OutputLength) {
    const ULONG Capacity = OutputLength <= FIELD_OFFSET(MDV2_LIST_OUTPUT, Records)
        ? 0 : (OutputLength - FIELD_OFFSET(MDV2_LIST_OUTPUT, Records)) / sizeof(MDV2_RECORD);
    Mdv2InitHeader(&Output->Header, STATUS_SUCCESS, Mdv2SourceKernelStructure,
                   Mdv2ConfidenceMedium);
    if (Capacity == 0) return STATUS_BUFFER_TOO_SMALL;
    const ULONG Kind = Query->TargetId;
    auto Add = [&](PCWSTR Name, NTSTATUS Status = STATUS_SUCCESS) -> PMDV2_RECORD {
        if (Output->Header.ReturnedCount >= Capacity) return nullptr;
        PMDV2_RECORD Record = &Output->Records[Output->Header.ReturnedCount++];
        AdvancedInitRecord(Record, Kind, Name, Status);
        return Record;
    };

    if (Kind == ADVANCED_KIND_PTE) {
#ifdef _M_AMD64
        auto Record = Add(L"x64 page-table walk");
        if (Record) {
            const ULONG64 Va = Query->Cursor;
            Record->Address = Va; Record->Value[0] = __readcr3();
            Record->Value[1] = (Va >> 39) & 0x1ff; Record->Value[2] = (Va >> 30) & 0x1ff;
            Record->Value[3] = (Va >> 21) & 0x1ff; Record->Value[4] = (Va >> 12) & 0x1ff;
            Record->Value[5] = Va & 0xfff;
            RtlStringCchCopyW(Record->Detail, RTL_NUMBER_OF(Record->Detail),
                              L"CR3, PML4E, PDPTE, PDE, PTE indexes and page offset");
        }
#else
        Add(L"Page-table walk", STATUS_NOT_SUPPORTED);
#endif
    } else if (Kind == ADVANCED_KIND_VAD) {
        auto Record = Add(L"VAD-compatible region inventory");
        if (Record) {
            Record->ProcessId = Query->ProcessId;
            Record->Address = Query->Cursor;
            Record->Value[0] = Query->Flags;
            RtlStringCchCopyW(Record->Detail, RTL_NUMBER_OF(Record->Detail),
                              L"Use ENUM_MEMORY_V2 for stable region boundaries; raw MMVAD layout is build dependent");
        }
    } else if (Kind == ADVANCED_KIND_THREAD_STACK) {
        auto Record = Add(L"Thread stack evidence");
        if (Record) {
            Record->ProcessId = Query->ProcessId; Record->ThreadId = Query->TargetId;
            Record->Address = Query->Cursor;
            RtlStringCchCopyW(Record->Detail, RTL_NUMBER_OF(Record->Detail),
                              L"Correlate ENUM_THREADS_V2 start address with kernel module ownership");
        }
    } else if (Kind == ADVANCED_KIND_HARDWARE) {
#ifdef _M_AMD64
        int Cpu[4] = {};
        __cpuid(Cpu, 0);
        auto Vendor = Add(L"CPU vendor / maximum leaf");
        if (Vendor) { Vendor->Value[0] = (ULONG)Cpu[0]; Vendor->Value[1] = (ULONG)Cpu[1]; Vendor->Value[2] = (ULONG)Cpu[3]; Vendor->Value[3] = (ULONG)Cpu[2]; }
        __cpuid(Cpu, 1);
        auto Features = Add(L"CPU features / hypervisor");
        if (Features) { Features->Value[0] = (ULONG)Cpu[0]; Features->Value[1] = (ULONG)Cpu[2]; Features->Value[2] = (ULONG)Cpu[3]; Features->Flags = (Cpu[2] & (1u << 31)) ? 1u : 0u; }
        __cpuidex(Cpu, 7, 0);
        auto Extended = Add(L"Extended CPU features");
        if (Extended) { Extended->Value[0] = (ULONG)Cpu[1]; Extended->Value[1] = (ULONG)Cpu[2]; Extended->Value[2] = (ULONG)Cpu[3]; }
#else
        Add(L"CPU capabilities", STATUS_NOT_SUPPORTED);
#endif
    } else if (Kind == ADVANCED_KIND_FIRMWARE) {
        PPHYSICAL_MEMORY_RANGE Ranges = MmGetPhysicalMemoryRanges();
        if (!Ranges) Add(L"Physical memory map", STATUS_INSUFFICIENT_RESOURCES);
        else {
            for (ULONG I = 0; Ranges[I].NumberOfBytes.QuadPart && Output->Header.ReturnedCount < Capacity; ++I) {
                auto Record = Add(L"Physical RAM range");
                Record->Address = Ranges[I].BaseAddress.QuadPart;
                Record->SizeBytes = Ranges[I].NumberOfBytes.QuadPart;
                Record->Value[0] = I;
            }
            ExFreePool(Ranges);
        }
    } else if (Kind == ADVANCED_KIND_SYSTEM_TABLE || Kind == ADVANCED_KIND_DRIVER_DISPATCH ||
               Kind == ADVANCED_KIND_DRIVER_UNLOAD) {
        auto Record = Add(Kind == ADVANCED_KIND_SYSTEM_TABLE ? L"System table transaction" :
                          Kind == ADVANCED_KIND_DRIVER_DISPATCH ? L"Driver dispatch transaction" : L"Coordinated driver unload");
        if (Record) RtlStringCchCopyW(Record->Detail, RTL_NUMBER_OF(Record->Detail),
                                      L"Capture, apply, verify and rollback through ADVANCED_OPERATION_V3");
    } else return STATUS_INVALID_PARAMETER;

    Output->Header.TotalCount = Output->Header.ReturnedCount;
    Output->Header.RequiredSize = FIELD_OFFSET(MDV2_LIST_OUTPUT, Records) +
        Output->Header.ReturnedCount * sizeof(MDV2_RECORD);
    return STATUS_SUCCESS;
}

static NTSTATUS AdvancedOperation(PADVANCED_OPERATION_INPUT Input,
                                  PADVANCED_OPERATION_OUTPUT Output) {
    if (!Input || !Output || Input->Size < sizeof(*Input) || Input->Version != 3)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Output, sizeof(*Output)); Output->Size = sizeof(*Output); Output->Version = 3;
    Input->Name[RTL_NUMBER_OF(Input->Name) - 1] = L'\0';
    if (Input->Kind == ADVANCED_KIND_DRIVER_UNLOAD) {
        SERVICE_OPERATION_INPUT Service = {}; Service.Operation = 1; Service.ServiceType = 1;
        RtlStringCchCopyW(Service.ServiceName, RTL_NUMBER_OF(Service.ServiceName), Input->Name);
        Output->Status = ServiceOperation(&Service, nullptr, 0, nullptr);
        RtlStringCchCopyW(Output->Detail, RTL_NUMBER_OF(Output->Detail), L"ZwUnloadDriver completed");
        return Output->Status;
    }
    if (Input->Kind != ADVANCED_KIND_SYSTEM_TABLE && Input->Kind != ADVANCED_KIND_DRIVER_DISPATCH)
        return STATUS_NOT_SUPPORTED;
    if (!Input->Address || !MmIsAddressValid((PVOID)(ULONG_PTR)Input->Address)) return STATUS_ACCESS_VIOLATION;
    KIRQL Irql; KeAcquireSpinLock(&G_AdvancedTransactionLock, &Irql);
    PADVANCED_TRANSACTION_SLOT Slot = nullptr;
    if (Input->Operation == ADVANCED_OP_CAPTURE) {
        for (auto& Candidate : G_AdvancedTransactions) if (!Candidate.Active) { Slot = &Candidate; break; }
        if (Slot) {
            Slot->Active = TRUE; Slot->Kind = Input->Kind; Slot->TargetId = Input->TargetId;
            Slot->Address = (ULONG_PTR)Input->Address; Slot->Before = *(volatile ULONG64*)Slot->Address;
            Slot->After = Slot->Before; Slot->Id = InterlockedIncrement64(&G_AdvancedTransactionId);
        }
    } else {
        for (auto& Candidate : G_AdvancedTransactions)
            if (Candidate.Active && Candidate.Id == Input->TransactionId && Candidate.Kind == Input->Kind) { Slot = &Candidate; break; }
    }
    if (!Slot) { KeReleaseSpinLock(&G_AdvancedTransactionLock, Irql); return STATUS_NOT_FOUND; }
    Output->TransactionId = Slot->Id; Output->BeforeValue = Slot->Before;
    ULONG_PTR Address = Slot->Address; ULONG64 Desired = Slot->Before;
    if (Input->Operation == ADVANCED_OP_APPLY) Desired = Input->Value;
    KeReleaseSpinLock(&G_AdvancedTransactionLock, Irql);
    NTSTATUS Status = STATUS_SUCCESS;
    if (Input->Operation != ADVANCED_OP_CAPTURE) Status = KrnlWriteMemory((PVOID)Address, &Desired, sizeof(Desired), KrnlMemRwMdl);
    ULONG64 Verify = 0; if (NT_SUCCESS(Status)) Status = KrnlReadMemory((PVOID)Address, &Verify, sizeof(Verify));
    if (NT_SUCCESS(Status) && Verify != Desired) Status = STATUS_DATA_ERROR;
    Output->AfterValue = Verify; Output->Status = Status;
    RtlStringCchPrintfW(Output->Detail, RTL_NUMBER_OF(Output->Detail), L"address=%p operation=%lu", (PVOID)Address, Input->Operation);
    if (NT_SUCCESS(Status) && Input->Operation == ADVANCED_OP_ROLLBACK) {
        KeAcquireSpinLock(&G_AdvancedTransactionLock, &Irql); Slot->Active = FALSE; KeReleaseSpinLock(&G_AdvancedTransactionLock, Irql);
    }
    return Status;
}
