// Unified kernel hook manager. Pointer hooks use forwarding thunks; table and
// code hooks require a kernel-mode ProxyAddress supplied by the caller.

#define AEGIS_HOOK_MAX_SLOTS 32
#define AEGIS_HOOK_PATCH_BYTES 12

typedef struct _AEGIS_HOOK_IDTR { USHORT Limit; ULONG_PTR Base; } AEGIS_HOOK_IDTR;
typedef struct _AEGIS_IDT_GATE64 {
    USHORT OffsetLow; USHORT Selector; UCHAR Ist; UCHAR TypeAttributes;
    USHORT OffsetMiddle; ULONG OffsetHigh; ULONG Reserved;
} AEGIS_IDT_GATE64, *PAEGIS_IDT_GATE64;

typedef struct _AEGIS_HOOK_SLOT {
    BOOLEAN Used; BOOLEAN Busy;
    ULONG HookId; ULONG State; ULONG TargetKind; ULONG MajorFunction;
    ULONG TableIndex; ULONG Vector; ULONG Processor;
    PDRIVER_OBJECT DriverObject; PFAST_IO_DISPATCH FastIoDispatch;
    PVOID PatchAddress; PVOID OriginalAddress; PVOID ProxyAddress;
    LONG OriginalValue; LONG PatchedValue;
    UCHAR OriginalBytes[AEGIS_HOOK_PATCH_BYTES];
    UCHAR PatchedBytes[AEGIS_HOOK_PATCH_BYTES];
    volatile LONG ActiveCalls; volatile LONG64 HitCount;
    NTSTATUS LastStatus;
    WCHAR DriverName[128]; WCHAR Detail[256];
} AEGIS_HOOK_SLOT, *PAEGIS_HOOK_SLOT;

static AEGIS_HOOK_SLOT G_HookSlots[AEGIS_HOOK_MAX_SLOTS] = {};
static KSPIN_LOCK G_HookLock = {};
static ULONG G_NextHookId = 1;

static VOID HookCopyText(PWCHAR D, SIZE_T C, PCWSTR S) {
    if (D == NULL || C == 0) return; D[0] = L'\0';
    if (S != NULL) RtlStringCchCopyW(D, C, S);
}

static VOID HookNormalizeDriverName(PCWSTR Input, PWCHAR Output, SIZE_T Capacity) {
    if (Output == NULL || Capacity == 0) return; Output[0] = L'\0';
    if (Input == NULL) return;
    while (*Input == L' ' || *Input == L'\t') ++Input;
    static const WCHAR Prefix[] = L"\\Driver\\"; BOOLEAN Qualified = TRUE;
    for (ULONG I = 0; I < RTL_NUMBER_OF(Prefix) - 1; ++I) {
        if (Input[I] == L'\0' || RtlUpcaseUnicodeChar(Input[I]) !=
            RtlUpcaseUnicodeChar(Prefix[I])) { Qualified = FALSE; break; }
    }
    if (Qualified) Input += RTL_NUMBER_OF(Prefix) - 1;
    RtlStringCchCopyW(Output, Capacity, Input);
}

static BOOLEAN HookIsKernelAddress(PVOID Address) {
    return Address != NULL && (ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart;
}

static NTSTATUS HookReadBytes(PVOID Address, PVOID Buffer, ULONG Size) {
    if (Address == NULL || Buffer == NULL || Size == 0 || !MmIsAddressValid(Address))
        return STATUS_INVALID_ADDRESS;
    __try { RtlCopyMemory(Buffer, Address, Size); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

static NTSTATUS HookWriteBytes(PVOID Address, PVOID Buffer, ULONG Size) {
    if (Address == NULL || Buffer == NULL || Size == 0) return STATUS_INVALID_PARAMETER;
    PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
    if (Mdl == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    __try { MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess); }
    __except (EXCEPTION_EXECUTE_HANDLER) { IoFreeMdl(Mdl); return STATUS_ACCESS_VIOLATION; }
    PVOID Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL,
                                                 FALSE, NormalPagePriority);
    if (Mapped == NULL) { MmUnlockPages(Mdl); IoFreeMdl(Mdl); return STATUS_UNSUCCESSFUL; }
    RtlCopyMemory(Mapped, Buffer, Size); KeMemoryBarrier();
    MmUnmapLockedPages(Mapped, Mdl); MmUnlockPages(Mdl); IoFreeMdl(Mdl);
    return STATUS_SUCCESS;
}

static PAEGIS_HOOK_SLOT HookFindById(ULONG Id) {
    for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I)
        if (G_HookSlots[I].Used && G_HookSlots[I].HookId == Id) return &G_HookSlots[I];
    return NULL;
}

static NTSTATUS HookClaimById(ULONG Id, PAEGIS_HOOK_SLOT *Claimed) {
    if (Claimed == NULL) return STATUS_INVALID_PARAMETER; *Claimed = NULL;
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql);
    PAEGIS_HOOK_SLOT Slot = HookFindById(Id); NTSTATUS Status = STATUS_SUCCESS;
    if (Slot == NULL) Status = STATUS_NOT_FOUND;
    else if (Slot->Busy) Status = STATUS_DEVICE_BUSY;
    else { Slot->Busy = TRUE; *Claimed = Slot; }
    KeReleaseSpinLock(&G_HookLock, Irql); return Status;
}

static VOID HookRelease(PAEGIS_HOOK_SLOT Slot) {
    if (Slot == NULL) return; KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql);
    if (Slot->Used) Slot->Busy = FALSE; KeReleaseSpinLock(&G_HookLock, Irql);
}

static BOOLEAN HookSlotMatches(PAEGIS_HOOK_SLOT S, ULONG Kind, PDRIVER_OBJECT Driver,
                                ULONG Major, ULONG Index, ULONG Vector, PVOID Patch) {
    if (!S->Used || S->TargetKind != Kind) return FALSE;
    if (Kind == HOOK_TARGET_DRIVER_DISPATCH || Kind == HOOK_TARGET_FAST_IO)
        return S->DriverObject == Driver && S->MajorFunction == Major;
    if (Kind == HOOK_TARGET_SSDT)
        return S->TableIndex == Index &&
               ((S->Vector & HOOK_FLAG_SHADOW_SSDT) == (Vector & HOOK_FLAG_SHADOW_SSDT));
    if (Kind == HOOK_TARGET_IDT) return S->Vector == Vector && S->Processor == Index;
    return S->PatchAddress == Patch;
}

static NTSTATUS HookReserveSlot(ULONG Kind, PDRIVER_OBJECT Driver, ULONG Major,
                                ULONG Index, ULONG Vector, PVOID Patch,
                                PVOID Original, PVOID Proxy, PCWSTR DriverName,
                                PCWSTR Detail, PAEGIS_HOOK_SLOT *Reserved) {
    if (Reserved == NULL) return STATUS_INVALID_PARAMETER; *Reserved = NULL;
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); PAEGIS_HOOK_SLOT Free = NULL;
    for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I) {
        PAEGIS_HOOK_SLOT S = &G_HookSlots[I]; if (!S->Used && Free == NULL) Free = S;
        if (HookSlotMatches(S, Kind, Driver, Major, Index, Vector, Patch)) {
            KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_OBJECT_NAME_COLLISION;
        }
    }
    if (Free == NULL) { KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_QUOTA_EXCEEDED; }
    RtlZeroMemory(Free, sizeof(*Free)); Free->Used = TRUE; Free->Busy = TRUE;
    Free->HookId = G_NextHookId++; if (Free->HookId == 0) Free->HookId = G_NextHookId++;
    Free->State = HOOK_STATE_PREPARED; Free->TargetKind = Kind;
    Free->MajorFunction = Major; Free->TableIndex = Index; Free->Vector = Vector;
    Free->Processor = Kind == HOOK_TARGET_IDT ? Index : 0; Free->DriverObject = Driver;
    Free->PatchAddress = Patch; Free->OriginalAddress = Original; Free->ProxyAddress = Proxy;
    Free->LastStatus = STATUS_SUCCESS;
    HookCopyText(Free->DriverName, RTL_NUMBER_OF(Free->DriverName), DriverName);
    HookCopyText(Free->Detail, RTL_NUMBER_OF(Free->Detail), Detail);
    *Reserved = Free; KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
}

static VOID HookFailInstall(PAEGIS_HOOK_SLOT Slot, NTSTATUS Status, PHOOK_RECORD Result);
static VOID HookFillRecord(PAEGIS_HOOK_SLOT Slot, PHOOK_RECORD Record);

static NTSTATUS HookResolveDriver(PCWSTR DriverName, PDRIVER_OBJECT *DriverObject) {
    if (DriverObject == NULL || DriverName == NULL || DriverName[0] == L'\0')
        return STATUS_INVALID_PARAMETER;
    WCHAR Normalized[128] = {}; HookNormalizeDriverName(DriverName, Normalized, RTL_NUMBER_OF(Normalized));
    WCHAR ObjectName[160] = {}; NTSTATUS Status = RtlStringCchPrintfW(
        ObjectName, RTL_NUMBER_OF(ObjectName), L"\\Driver\\%ws", Normalized);
    if (!NT_SUCCESS(Status)) return Status; UNICODE_STRING Name; RtlInitUnicodeString(&Name, ObjectName);
    return ObReferenceObjectByName(&Name, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,
                                   KernelMode, NULL, (PVOID*)DriverObject);
}

static PAEGIS_HOOK_SLOT HookFindDispatch(PDRIVER_OBJECT Driver, ULONG Major) {
    for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I) {
        PAEGIS_HOOK_SLOT S = &G_HookSlots[I];
        if (S->Used && S->TargetKind == HOOK_TARGET_DRIVER_DISPATCH &&
            S->DriverObject == Driver && S->MajorFunction == Major) return S;
    }
    return NULL;
}

static NTSTATUS NTAPI AegisHookDispatchThunk(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Major = Stack != NULL ? Stack->MajorFunction : 0;
    PDRIVER_OBJECT Driver = DeviceObject != NULL ? DeviceObject->DriverObject : NULL;
    PDRIVER_DISPATCH Original = NULL; PAEGIS_HOOK_SLOT Slot = NULL; KIRQL Irql;
    KeAcquireSpinLock(&G_HookLock, &Irql); Slot = HookFindDispatch(Driver, Major);
    if (Slot != NULL) { Original = (PDRIVER_DISPATCH)Slot->OriginalAddress;
        InterlockedIncrement(&Slot->ActiveCalls); InterlockedIncrement64(&Slot->HitCount); }
    KeReleaseSpinLock(&G_HookLock, Irql);
    NTSTATUS Status = Original != NULL ? Original(DeviceObject, Irp) : STATUS_INVALID_DEVICE_REQUEST;
    if (Slot != NULL) InterlockedDecrement(&Slot->ActiveCalls); return Status;
}

static PAEGIS_HOOK_SLOT HookFindFastIo(PDRIVER_OBJECT Driver) {
    for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I) {
        PAEGIS_HOOK_SLOT S = &G_HookSlots[I];
        if (S->Used && S->TargetKind == HOOK_TARGET_FAST_IO && S->DriverObject == Driver) return S;
    }
    return NULL;
}

static BOOLEAN AegisFastIoCheckIfPossible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset,
    ULONG Length, BOOLEAN Wait, ULONG LockKey, BOOLEAN Read, PIO_STATUS_BLOCK IoStatus,
    PDEVICE_OBJECT DeviceObject) {
    PDRIVER_OBJECT Driver = DeviceObject != NULL ? DeviceObject->DriverObject : NULL;
    PFAST_IO_CHECK_IF_POSSIBLE Original = NULL; PAEGIS_HOOK_SLOT Slot = NULL; KIRQL Irql;
    KeAcquireSpinLock(&G_HookLock, &Irql); Slot = HookFindFastIo(Driver);
    if (Slot != NULL) { Original = (PFAST_IO_CHECK_IF_POSSIBLE)Slot->OriginalAddress;
        InterlockedIncrement(&Slot->ActiveCalls); InterlockedIncrement64(&Slot->HitCount); }
    KeReleaseSpinLock(&G_HookLock, Irql);
    BOOLEAN Result = Original != NULL ? Original(FileObject, FileOffset, Length, Wait,
        LockKey, Read, IoStatus, DeviceObject) : FALSE;
    if (Slot != NULL) InterlockedDecrement(&Slot->ActiveCalls); return Result;
}

static NTSTATUS HookInstallDispatch(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
    if (Request->MajorFunction > IRP_MJ_MAXIMUM_FUNCTION) return STATUS_INVALID_PARAMETER;
    PDRIVER_OBJECT Driver = NULL; NTSTATUS Status = HookResolveDriver(Request->DriverName, &Driver);
    if (!NT_SUCCESS(Status)) return Status; PDRIVER_DISPATCH Original = Driver->MajorFunction[Request->MajorFunction];
    if (Original == NULL) { ObDereferenceObject(Driver); return STATUS_NOT_FOUND; }
    WCHAR Detail[256] = {}; RtlStringCchPrintfW(Detail, RTL_NUMBER_OF(Detail), L"MajorFunction %lu", Request->MajorFunction);
    PAEGIS_HOOK_SLOT Slot = NULL; Status = HookReserveSlot(HOOK_TARGET_DRIVER_DISPATCH, Driver,
        Request->MajorFunction, 0, 0, &Driver->MajorFunction[Request->MajorFunction], Original,
        (PVOID)AegisHookDispatchThunk, Request->DriverName, Detail, &Slot);
    if (!NT_SUCCESS(Status)) { ObDereferenceObject(Driver); return Status; }
    PVOID Proxy = (PVOID)AegisHookDispatchThunk; Status = HookWriteBytes(Slot->PatchAddress, &Proxy, sizeof(Proxy));
    if (!NT_SUCCESS(Status)) { HookFailInstall(Slot, Status, Result); return Status; }
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_ACTIVE; Slot->Busy = FALSE; HookFillRecord(Slot, Result); KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
}

static NTSTATUS HookInstallFastIo(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
    if (Request->TableIndex != HOOK_FAST_IO_CHECK_IF_POSSIBLE) return STATUS_NOT_SUPPORTED;
    PDRIVER_OBJECT Driver = NULL; NTSTATUS Status = HookResolveDriver(Request->DriverName, &Driver);
    if (!NT_SUCCESS(Status)) return Status; PFAST_IO_DISPATCH FastIo = Driver->FastIoDispatch;
    if (FastIo == NULL || FastIo->SizeOfFastIoDispatch < FIELD_OFFSET(FAST_IO_DISPATCH, FastIoCheckIfPossible) + sizeof(PVOID) || FastIo->FastIoCheckIfPossible == NULL) {
        ObDereferenceObject(Driver); return STATUS_NOT_FOUND;
    }
    PVOID Original = (PVOID)FastIo->FastIoCheckIfPossible; PAEGIS_HOOK_SLOT Slot = NULL;
    Status = HookReserveSlot(HOOK_TARGET_FAST_IO, Driver, 0, Request->TableIndex, 0,
        &FastIo->FastIoCheckIfPossible, Original, (PVOID)AegisFastIoCheckIfPossible,
        Request->DriverName, L"FastIoCheckIfPossible", &Slot);
    if (!NT_SUCCESS(Status)) { ObDereferenceObject(Driver); return Status; }
    Slot->FastIoDispatch = FastIo; PVOID Proxy = (PVOID)AegisFastIoCheckIfPossible;
    Status = HookWriteBytes(Slot->PatchAddress, &Proxy, sizeof(Proxy));
    if (!NT_SUCCESS(Status)) { HookFailInstall(Slot, Status, Result); return Status; }
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_ACTIVE; Slot->Busy = FALSE; HookFillRecord(Slot, Result); KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
}

static NTSTATUS HookGetTables(PSYSTEM_TABLES_OUTPUT Tables) {
    ULONG Bytes = 0; RtlZeroMemory(Tables, sizeof(*Tables)); return QuerySystemTables(Tables, sizeof(*Tables), &Bytes);
}

static NTSTATUS HookInstallSsdt(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
#ifndef _M_AMD64
    UNREFERENCED_PARAMETER(Request); UNREFERENCED_PARAMETER(Result); return STATUS_NOT_SUPPORTED;
#else
    if (!HookIsKernelAddress((PVOID)(ULONG_PTR)Request->ProxyAddress)) return STATUS_INVALID_PARAMETER;
    SYSTEM_TABLES_OUTPUT Tables = {}; NTSTATUS Status = HookGetTables(&Tables); if (!NT_SUCCESS(Status)) return Status;
    ULONG_PTR Base = (Request->Flags & HOOK_FLAG_SHADOW_SSDT) ? Tables.ShadowSsdtBase : Tables.SsdtBase;
    ULONG Count = (Request->Flags & HOOK_FLAG_SHADOW_SSDT) ? Tables.ShadowSsdtCount : Tables.SsdtCount;
    if (Base == 0 || Request->TableIndex >= Count) return STATUS_NOT_FOUND;
    PLONG Entry = (PLONG)(Base + Request->TableIndex * sizeof(LONG)); LONG OriginalValue = 0;
    Status = HookReadBytes(Entry, &OriginalValue, sizeof(OriginalValue)); if (!NT_SUCCESS(Status)) return Status;
    LONG_PTR Relative = (LONG_PTR)Request->ProxyAddress - (LONG_PTR)Base;
    if (Relative < -(1LL << 27) || Relative >= (1LL << 27)) return STATUS_INTEGER_OVERFLOW;
    LONGLONG Encoded = ((LONGLONG)Relative) << 4; if (Encoded < MINLONG || Encoded > MAXLONG) return STATUS_INTEGER_OVERFLOW;
    LONG PatchedValue = (LONG)Encoded; PVOID OriginalAddress = (PVOID)(Base + ((LONG_PTR)OriginalValue >> 4));
    PAEGIS_HOOK_SLOT Slot = NULL; Status = HookReserveSlot(HOOK_TARGET_SSDT, NULL, 0, Request->TableIndex, Request->Flags,
        Entry, OriginalAddress, (PVOID)(ULONG_PTR)Request->ProxyAddress, NULL,
        (Request->Flags & HOOK_FLAG_SHADOW_SSDT) ? L"Shadow SSDT" : L"SSDT", &Slot);
    if (!NT_SUCCESS(Status)) return Status; Slot->OriginalValue = OriginalValue; Slot->PatchedValue = PatchedValue;
    Status = HookWriteBytes(Entry, &PatchedValue, sizeof(PatchedValue)); if (!NT_SUCCESS(Status)) { HookFailInstall(Slot, Status, Result); return Status; }
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_ACTIVE; Slot->Busy = FALSE; HookFillRecord(Slot, Result); KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
#endif
}

static ULONG_PTR HookIdtGateTarget(const AEGIS_IDT_GATE64 &Gate) { return (ULONG_PTR)Gate.OffsetLow | ((ULONG_PTR)Gate.OffsetMiddle << 16) | ((ULONG_PTR)Gate.OffsetHigh << 32); }
static VOID HookSetIdtGateTarget(PAEGIS_IDT_GATE64 Gate, ULONG_PTR Target) { Gate->OffsetLow = (USHORT)Target; Gate->OffsetMiddle = (USHORT)(Target >> 16); Gate->OffsetHigh = (ULONG)(Target >> 32); }

static NTSTATUS HookInstallIdt(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
#ifndef _M_AMD64
    UNREFERENCED_PARAMETER(Request); UNREFERENCED_PARAMETER(Result); return STATUS_NOT_SUPPORTED;
#else
    if (Request->Vector >= 256 || !HookIsKernelAddress((PVOID)(ULONG_PTR)Request->ProxyAddress)) return STATUS_INVALID_PARAMETER;
    AEGIS_HOOK_IDTR Idtr = {}; __sidt(&Idtr); if (Idtr.Base == 0 || Request->Vector * 16 > Idtr.Limit) return STATUS_NOT_FOUND;
    PAEGIS_IDT_GATE64 Gate = (PAEGIS_IDT_GATE64)(Idtr.Base + Request->Vector * 16); AEGIS_IDT_GATE64 Original = {};
    NTSTATUS Status = HookReadBytes(Gate, &Original, sizeof(Original)); if (!NT_SUCCESS(Status)) return Status;
    if (!(Original.TypeAttributes & 0x80)) return STATUS_NOT_FOUND; AEGIS_IDT_GATE64 Patched = Original; HookSetIdtGateTarget(&Patched, (ULONG_PTR)Request->ProxyAddress);
    ULONG Cpu = KeGetCurrentProcessorNumber(); PAEGIS_HOOK_SLOT Slot = NULL; Status = HookReserveSlot(HOOK_TARGET_IDT, NULL, 0, Cpu, Request->Vector,
        Gate, (PVOID)HookIdtGateTarget(Original), (PVOID)(ULONG_PTR)Request->ProxyAddress, NULL, L"IDT current CPU", &Slot);
    if (!NT_SUCCESS(Status)) return Status; RtlCopyMemory(Slot->OriginalBytes, &Original, sizeof(Slot->OriginalBytes)); RtlCopyMemory(Slot->PatchedBytes, &Patched, sizeof(Slot->PatchedBytes));
    Status = HookWriteBytes(Gate, &Patched, sizeof(Patched)); if (!NT_SUCCESS(Status)) { HookFailInstall(Slot, Status, Result); return Status; }
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_ACTIVE; Slot->Busy = FALSE; HookFillRecord(Slot, Result); KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
#endif
}

static VOID HookBuildInlineJump(PUCHAR Buffer, PVOID Proxy) { Buffer[0] = 0x48; Buffer[1] = 0xB8; *(ULONG64 *)(Buffer + 2) = (ULONG64)(ULONG_PTR)Proxy; Buffer[10] = 0xFF; Buffer[11] = 0xE0; }

static NTSTATUS HookInstallInline(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
#ifndef _M_AMD64
    UNREFERENCED_PARAMETER(Request); UNREFERENCED_PARAMETER(Result); return STATUS_NOT_SUPPORTED;
#else
    PVOID Target = (PVOID)(ULONG_PTR)Request->TargetAddress; PVOID Proxy = (PVOID)(ULONG_PTR)Request->ProxyAddress;
    if (!HookIsKernelAddress(Target) || !HookIsKernelAddress(Proxy)) return STATUS_INVALID_PARAMETER;
    UCHAR Original[AEGIS_HOOK_PATCH_BYTES] = {}; NTSTATUS Status = HookReadBytes(Target, Original, sizeof(Original)); if (!NT_SUCCESS(Status)) return Status;
    UCHAR Patched[AEGIS_HOOK_PATCH_BYTES] = {}; HookBuildInlineJump(Patched, Proxy); PAEGIS_HOOK_SLOT Slot = NULL;
    Status = HookReserveSlot(HOOK_TARGET_INLINE, NULL, 0, 0, 0, Target, Target, Proxy, NULL, L"12-byte absolute jump", &Slot); if (!NT_SUCCESS(Status)) return Status;
    RtlCopyMemory(Slot->OriginalBytes, Original, sizeof(Original)); RtlCopyMemory(Slot->PatchedBytes, Patched, sizeof(Patched));
    Status = HookWriteBytes(Target, Patched, sizeof(Patched)); if (!NT_SUCCESS(Status)) { HookFailInstall(Slot, Status, Result); return Status; }
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_ACTIVE; Slot->Busy = FALSE; HookFillRecord(Slot, Result); KeReleaseSpinLock(&G_HookLock, Irql); return STATUS_SUCCESS;
#endif
}

static NTSTATUS HookRestoreSlot(PAEGIS_HOOK_SLOT Slot) {
    if (Slot == NULL || !Slot->Used) return STATUS_NOT_FOUND; NTSTATUS Status = STATUS_SUCCESS;
    if (Slot->TargetKind == HOOK_TARGET_DRIVER_DISPATCH || Slot->TargetKind == HOOK_TARGET_FAST_IO) {
        PVOID Current = NULL; Status = HookReadBytes(Slot->PatchAddress, &Current, sizeof(Current)); if (!NT_SUCCESS(Status)) return Status;
        if (Current != Slot->ProxyAddress && Current != Slot->OriginalAddress) return STATUS_DATA_ERROR;
        if (Current == Slot->ProxyAddress) Status = HookWriteBytes(Slot->PatchAddress, &Slot->OriginalAddress, sizeof(Slot->OriginalAddress));
        if (!NT_SUCCESS(Status)) return Status; LARGE_INTEGER Delay; Delay.QuadPart = -10 * 10000;
        for (ULONG A = 0; A < 100 && InterlockedCompareExchange(&Slot->ActiveCalls, 0, 0) != 0; ++A) KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        if (InterlockedCompareExchange(&Slot->ActiveCalls, 0, 0) != 0) return STATUS_DEVICE_BUSY;
        KeMemoryBarrier(); KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        if (InterlockedCompareExchange(&Slot->ActiveCalls, 0, 0) != 0) return STATUS_DEVICE_BUSY;
    } else if (Slot->TargetKind == HOOK_TARGET_SSDT) {
        LONG Current = 0; Status = HookReadBytes(Slot->PatchAddress, &Current, sizeof(Current)); if (!NT_SUCCESS(Status)) return Status;
        if (Current != Slot->PatchedValue && Current != Slot->OriginalValue) return STATUS_DATA_ERROR;
        if (Current == Slot->PatchedValue) Status = HookWriteBytes(Slot->PatchAddress, &Slot->OriginalValue, sizeof(Slot->OriginalValue));
    } else if (Slot->TargetKind == HOOK_TARGET_IDT || Slot->TargetKind == HOOK_TARGET_INLINE) {
        UCHAR Current[AEGIS_HOOK_PATCH_BYTES] = {}; Status = HookReadBytes(Slot->PatchAddress, Current, sizeof(Current)); if (!NT_SUCCESS(Status)) return Status;
        if (RtlCompareMemory(Current, Slot->PatchedBytes, sizeof(Current)) != sizeof(Current) && RtlCompareMemory(Current, Slot->OriginalBytes, sizeof(Current)) != sizeof(Current)) return STATUS_DATA_ERROR;
        if (RtlCompareMemory(Current, Slot->PatchedBytes, sizeof(Current)) == sizeof(Current)) Status = HookWriteBytes(Slot->PatchAddress, Slot->OriginalBytes, sizeof(Slot->OriginalBytes));
    } else return STATUS_NOT_SUPPORTED;
    if (!NT_SUCCESS(Status)) return Status; PDRIVER_OBJECT Driver = NULL; KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_RESTORED; Slot->LastStatus = STATUS_SUCCESS; Driver = Slot->DriverObject; Slot->DriverObject = NULL; KeReleaseSpinLock(&G_HookLock, Irql); if (Driver != NULL) ObDereferenceObject(Driver); return STATUS_SUCCESS;
}

static VOID HookFailInstall(PAEGIS_HOOK_SLOT Slot, NTSTATUS Status, PHOOK_RECORD Result) {
    if (Slot == NULL) return; PDRIVER_OBJECT Driver = NULL; KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->State = HOOK_STATE_FAILED; Slot->LastStatus = Status; if (Result != NULL) HookFillRecord(Slot, Result); Driver = Slot->DriverObject; RtlZeroMemory(Slot, sizeof(*Slot)); KeReleaseSpinLock(&G_HookLock, Irql); if (Driver != NULL) ObDereferenceObject(Driver);
}

static ULONG_PTR HookRecordTarget(PAEGIS_HOOK_SLOT Slot) {
    if (Slot->State == HOOK_STATE_RESTORED)
        return (ULONG_PTR)Slot->OriginalAddress;
    if (Slot->TargetKind == HOOK_TARGET_INLINE) return (ULONG_PTR)Slot->PatchAddress;
    if (Slot->TargetKind == HOOK_TARGET_SSDT) { LONG V = 0; if (NT_SUCCESS(HookReadBytes(Slot->PatchAddress, &V, sizeof(V)))) { ULONG_PTR Base = (ULONG_PTR)Slot->PatchAddress - (Slot->TableIndex * sizeof(LONG)); return (ULONG_PTR)(Base + ((LONG_PTR)V >> 4)); } }
    if (Slot->TargetKind == HOOK_TARGET_IDT) { AEGIS_IDT_GATE64 G = {}; if (NT_SUCCESS(HookReadBytes(Slot->PatchAddress, &G, sizeof(G)))) return HookIdtGateTarget(G); }
    if (Slot->PatchAddress != NULL) { PVOID V = NULL; if (NT_SUCCESS(HookReadBytes(Slot->PatchAddress, &V, sizeof(V)))) return (ULONG_PTR)V; }
    return (ULONG_PTR)Slot->OriginalAddress;
}

static VOID HookFillRecord(PAEGIS_HOOK_SLOT Slot, PHOOK_RECORD Record) {
    if (Slot == NULL || Record == NULL) return; RtlZeroMemory(Record, sizeof(*Record)); Record->Size = sizeof(*Record); Record->Version = HOOK_PROTOCOL_VERSION;
    Record->HookId = Slot->HookId; Record->State = Slot->State; Record->TargetKind = Slot->TargetKind; Record->MajorFunction = Slot->MajorFunction; Record->TableIndex = Slot->TableIndex; Record->Vector = Slot->Vector;
    Record->TargetAddress = HookRecordTarget(Slot); Record->OriginalAddress = (ULONG64)(ULONG_PTR)Slot->OriginalAddress; Record->ProxyAddress = (ULONG64)(ULONG_PTR)Slot->ProxyAddress;
    Record->HitCount = (ULONG64)InterlockedCompareExchange64(&Slot->HitCount, 0, 0); Record->ActiveCalls = (ULONG)InterlockedCompareExchange(&Slot->ActiveCalls, 0, 0); Record->Status = Slot->LastStatus; Record->Flags = Slot->Vector & HOOK_FLAG_SHADOW_SSDT;
    HookCopyText(Record->DriverName, RTL_NUMBER_OF(Record->DriverName), Slot->DriverName); HookCopyText(Record->Detail, RTL_NUMBER_OF(Record->Detail), Slot->Detail);
}

static NTSTATUS HookOperate(PHOOK_REQUEST Request, PHOOK_RECORD Result) {
    if (Request == NULL || Request->Version != HOOK_PROTOCOL_VERSION || Request->Size < sizeof(HOOK_REQUEST)) return STATUS_REVISION_MISMATCH;
    if (Result != NULL) RtlZeroMemory(Result, sizeof(*Result));
    if (Request->Operation == HOOK_OP_INSTALL) {
        switch (Request->TargetKind) { case HOOK_TARGET_DRIVER_DISPATCH: return HookInstallDispatch(Request, Result); case HOOK_TARGET_FAST_IO: return HookInstallFastIo(Request, Result); case HOOK_TARGET_SSDT: return HookInstallSsdt(Request, Result); case HOOK_TARGET_IDT: return HookInstallIdt(Request, Result); case HOOK_TARGET_INLINE: return HookInstallInline(Request, Result); default: return STATUS_NOT_SUPPORTED; }
    }
    PAEGIS_HOOK_SLOT Slot = NULL; NTSTATUS Status = HookClaimById(Request->HookId, &Slot); if (!NT_SUCCESS(Status)) return Status;
    if (Request->Operation == HOOK_OP_REMOVE) { Status = HookRestoreSlot(Slot); KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->LastStatus = Status; if (Result != NULL) HookFillRecord(Slot, Result); if (Result != NULL) Result->Status = Status; if (NT_SUCCESS(Status)) RtlZeroMemory(Slot, sizeof(*Slot)); KeReleaseSpinLock(&G_HookLock, Irql); if (!NT_SUCCESS(Status)) HookRelease(Slot); return Status; }
    if (Request->Operation == HOOK_OP_ENABLE || Request->Operation == HOOK_OP_DISABLE) {
        BOOLEAN Enable = Request->Operation == HOOK_OP_ENABLE; PVOID Current = NULL; PVOID Desired = Enable ? Slot->ProxyAddress : Slot->OriginalAddress;
        if (Slot->TargetKind == HOOK_TARGET_SSDT) { LONG V = 0; Status = HookReadBytes(Slot->PatchAddress, &V, sizeof(V)); if (NT_SUCCESS(Status) && V != (Enable ? Slot->OriginalValue : Slot->PatchedValue)) Status = STATUS_DATA_ERROR; if (NT_SUCCESS(Status)) { LONG NewV = Enable ? Slot->PatchedValue : Slot->OriginalValue; Status = HookWriteBytes(Slot->PatchAddress, &NewV, sizeof(NewV)); } }
        else if (Slot->TargetKind == HOOK_TARGET_IDT || Slot->TargetKind == HOOK_TARGET_INLINE) { UCHAR V[AEGIS_HOOK_PATCH_BYTES] = {}; Status = HookReadBytes(Slot->PatchAddress, V, sizeof(V)); const UCHAR *Expected = Enable ? Slot->OriginalBytes : Slot->PatchedBytes; const UCHAR *NewV = Enable ? Slot->PatchedBytes : Slot->OriginalBytes; if (NT_SUCCESS(Status) && RtlCompareMemory(V, Expected, sizeof(V)) != sizeof(V)) Status = STATUS_DATA_ERROR; if (NT_SUCCESS(Status)) Status = HookWriteBytes(Slot->PatchAddress, (PVOID)NewV, sizeof(V)); }
        else { Status = HookReadBytes(Slot->PatchAddress, &Current, sizeof(Current)); if (NT_SUCCESS(Status) && Current != (Enable ? Slot->OriginalAddress : Slot->ProxyAddress)) Status = STATUS_DATA_ERROR; if (NT_SUCCESS(Status)) Status = HookWriteBytes(Slot->PatchAddress, &Desired, sizeof(Desired)); }
        if (NT_SUCCESS(Status)) Slot->State = Enable ? HOOK_STATE_ACTIVE : HOOK_STATE_DISABLED;
    } else if (Request->Operation == HOOK_OP_VERIFY) {
        if (Slot->TargetKind == HOOK_TARGET_SSDT) { LONG V = 0; Status = HookReadBytes(Slot->PatchAddress, &V, sizeof(V)); if (NT_SUCCESS(Status) && V != Slot->PatchedValue && !(Slot->State == HOOK_STATE_DISABLED && V == Slot->OriginalValue)) Status = STATUS_DATA_ERROR; }
        else if (Slot->TargetKind == HOOK_TARGET_IDT || Slot->TargetKind == HOOK_TARGET_INLINE) { UCHAR V[AEGIS_HOOK_PATCH_BYTES] = {}; Status = HookReadBytes(Slot->PatchAddress, V, sizeof(V)); const UCHAR *E = Slot->State == HOOK_STATE_DISABLED ? Slot->OriginalBytes : Slot->PatchedBytes; if (NT_SUCCESS(Status) && RtlCompareMemory(V, E, sizeof(V)) != sizeof(V)) Status = STATUS_DATA_ERROR; }
        else { PVOID V = NULL; Status = HookReadBytes(Slot->PatchAddress, &V, sizeof(V)); if (NT_SUCCESS(Status) && V != (Slot->State == HOOK_STATE_DISABLED ? Slot->OriginalAddress : Slot->ProxyAddress)) Status = STATUS_DATA_ERROR; }
    } else Status = STATUS_INVALID_PARAMETER;
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); Slot->LastStatus = Status; if (Result != NULL) HookFillRecord(Slot, Result); if (Result != NULL) Result->Status = Status; KeReleaseSpinLock(&G_HookLock, Irql); HookRelease(Slot); return Status;
}

static NTSTATUS HookEnumerate(PVOID OutputBuffer, ULONG OutputLength, PULONG BytesReturned) {
    if (OutputBuffer == NULL || BytesReturned == NULL || OutputLength < FIELD_OFFSET(HOOK_ENUM_OUTPUT, Records)) return STATUS_BUFFER_TOO_SMALL;
    PHOOK_ENUM_OUTPUT Output = (PHOOK_ENUM_OUTPUT)OutputBuffer; RtlZeroMemory(Output, OutputLength); Output->Size = sizeof(*Output); Output->Version = HOOK_PROTOCOL_VERSION; Output->Capacity = (OutputLength - FIELD_OFFSET(HOOK_ENUM_OUTPUT, Records)) / sizeof(HOOK_RECORD);
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS && Output->Count < Output->Capacity; ++I) if (G_HookSlots[I].Used) HookFillRecord(&G_HookSlots[I], &Output->Records[Output->Count++]); KeReleaseSpinLock(&G_HookLock, Irql);
    *BytesReturned = FIELD_OFFSET(HOOK_ENUM_OUTPUT, Records) + Output->Count * sizeof(HOOK_RECORD); return STATUS_SUCCESS;
}

static NTSTATUS HookRestoreAll() {
    NTSTATUS FirstFailure = STATUS_SUCCESS; LARGE_INTEGER Delay; Delay.QuadPart = -10 * 10000;
    for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I) { PAEGIS_HOOK_SLOT Slot = &G_HookSlots[I]; BOOLEAN Claimed = FALSE;
        for (ULONG A = 0; A < 200 && !Claimed; ++A) { KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); if (!Slot->Used) { KeReleaseSpinLock(&G_HookLock, Irql); break; } if (!Slot->Busy) { Slot->Busy = TRUE; Claimed = TRUE; } KeReleaseSpinLock(&G_HookLock, Irql); if (!Claimed) KeDelayExecutionThread(KernelMode, FALSE, &Delay); }
        if (!Claimed) { if (Slot->Used && NT_SUCCESS(FirstFailure)) FirstFailure = STATUS_DEVICE_BUSY; continue; }
        NTSTATUS Status = HookRestoreSlot(Slot); if (!NT_SUCCESS(Status) && NT_SUCCESS(FirstFailure)) FirstFailure = Status; if (NT_SUCCESS(Status)) { KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); RtlZeroMemory(Slot, sizeof(*Slot)); KeReleaseSpinLock(&G_HookLock, Irql); } else HookRelease(Slot);
    } return FirstFailure;
}

static NTSTATUS HookQueryCapabilities(PHOOK_CAPABILITIES_OUTPUT Output) {
    if (Output == NULL || Output->Size < sizeof(HOOK_CAPABILITIES_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(Output, sizeof(*Output)); Output->Size = sizeof(*Output); Output->Version = HOOK_PROTOCOL_VERSION;
    Output->SupportedTargets = (1u << HOOK_TARGET_DRIVER_DISPATCH) | (1u << HOOK_TARGET_FAST_IO) | (1u << HOOK_TARGET_SSDT) | (1u << HOOK_TARGET_IDT) | (1u << HOOK_TARGET_INLINE);
    Output->SupportedOperations = (1u << HOOK_OP_INSTALL) | (1u << HOOK_OP_ENABLE) | (1u << HOOK_OP_DISABLE) | (1u << HOOK_OP_REMOVE) | (1u << HOOK_OP_VERIFY) | (1u << HOOK_OP_RESTORE_ALL); Output->MaxHooks = AEGIS_HOOK_MAX_SLOTS;
    KIRQL Irql; KeAcquireSpinLock(&G_HookLock, &Irql); for (ULONG I = 0; I < AEGIS_HOOK_MAX_SLOTS; ++I) if (G_HookSlots[I].Used && G_HookSlots[I].State == HOOK_STATE_ACTIVE) ++Output->ActiveHooks; KeReleaseSpinLock(&G_HookLock, Irql); Output->LastStatus = STATUS_SUCCESS; return STATUS_SUCCESS;
}
