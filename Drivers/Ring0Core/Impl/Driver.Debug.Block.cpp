
static volatile UCHAR  G_DbgBlockActive    = 0;
static BOOLEAN         G_DbgBlockHooked    = FALSE;
static PVOID           G_DbgBlockHandler   = NULL;
static PVOID           G_DbgBlockTarget    = NULL;
static UCHAR           G_DbgBlockSaved[24] = {};

#define DBGBLOCK_HANDLER_SIZE 16
#define DBGBLOCK_HOOK_SIZE    12
#define DBGBLOCK_SAVE_SIZE    24

static const UCHAR DbgBlockHandlerTmpl[DBGBLOCK_HANDLER_SIZE] = {
    0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x74, 0x06,
    0xC3,
    0xB8, 0x22, 0x00, 0x00, 0xC0,
    0xC3,
};

static VOID DbgBlockBuildHook(PUCHAR Out, PVOID Dest)
{
    Out[0]  = 0x48; Out[1]  = 0xB8;
    *(PULONG64)(Out + 2) = (ULONG64)Dest;
    Out[10] = 0xFF; Out[11] = 0xE0;
}

static VOID DbgBlockPatchHandler(VOID)
{
    if (G_DbgBlockHandler == NULL) return;
    PUCHAR H = (PUCHAR)G_DbgBlockHandler;
    *(PLONG)(H + 2) = (LONG)((PUCHAR)&G_DbgBlockActive - (H + 7));
}

static NTSTATUS DbgBlockWriteSafe(PVOID Dest, PVOID Src, ULONG Size)
{
    PMDL Mdl = IoAllocateMdl(Dest, Size, FALSE, FALSE, NULL);
    if (Mdl == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(Mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID Mapped = MmMapLockedPagesSpecifyCache(
        Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (Mapped == NULL) {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(Mapped, Src, Size);

    MmUnmapLockedPages(Mapped, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    return STATUS_SUCCESS;
}

static NTSTATUS DbgBlockInstall(VOID)
{
    if (G_DbgBlockHooked) {
        G_DbgBlockActive = 1;
        LogMessage("DbgBlock: already installed, blocking re-enabled.\n");
        return STATUS_SUCCESS;
    }

    if (G_DbgBlockTarget == NULL) {
        UNICODE_STRING U;
        RtlInitUnicodeString(&U, L"KdSystemDebugControl");
        G_DbgBlockTarget = MmGetSystemRoutineAddress(&U);
        if (G_DbgBlockTarget == NULL) {
            LogMessage("DbgBlock: KdSystemDebugControl not exported.\n");
            return STATUS_NOT_FOUND;
        }
        LogMessage("DbgBlock: KdSystemDebugControl = %p\n", G_DbgBlockTarget);
    }

    if (G_DbgBlockHandler == NULL) {
        if (!NT_SUCCESS(KrnlReadMemory(G_DbgBlockTarget, G_DbgBlockSaved, DBGBLOCK_SAVE_SIZE))) {
            LogMessage("DbgBlock: read original bytes failed.\n");
            return STATUS_UNSUCCESSFUL;
        }
        LogMessage("DbgBlock: saved [0]=%02X [4]=%02X [8]=%02X [12]=%02X [20]=%02X [23]=%02X\n",
            G_DbgBlockSaved[0], G_DbgBlockSaved[4], G_DbgBlockSaved[8],
            G_DbgBlockSaved[12], G_DbgBlockSaved[20], G_DbgBlockSaved[23]);

        G_DbgBlockHandler = ExAllocatePool2(
            POOL_FLAG_NON_PAGED_EXECUTE, DBGBLOCK_HANDLER_SIZE, 'glBD');
        if (G_DbgBlockHandler == NULL) {
            LogMessage("DbgBlock: handler alloc failed.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(G_DbgBlockHandler, DbgBlockHandlerTmpl, DBGBLOCK_HANDLER_SIZE);
        DbgBlockPatchHandler();
    } else {
        LogMessage("DbgBlock: reusing existing handler.\n");
    }

    G_DbgBlockActive = 1;

    UCHAR Hook[DBGBLOCK_HOOK_SIZE];
    DbgBlockBuildHook(Hook, G_DbgBlockHandler);
    if (!NT_SUCCESS(DbgBlockWriteSafe(G_DbgBlockTarget, Hook, DBGBLOCK_HOOK_SIZE))) {
        LogMessage("DbgBlock: hook write failed.\n");
        G_DbgBlockActive = 0;
        return STATUS_UNSUCCESSFUL;
    }

    UCHAR Verify[DBGBLOCK_HOOK_SIZE];
    if (!NT_SUCCESS(KrnlReadMemory(G_DbgBlockTarget, Verify, DBGBLOCK_HOOK_SIZE)) ||
        RtlCompareMemory(Verify, Hook, DBGBLOCK_HOOK_SIZE) != DBGBLOCK_HOOK_SIZE) {
        LogMessage("DbgBlock: hook verification failed.\n");
        G_DbgBlockActive = 0;
        return STATUS_UNSUCCESSFUL;
    }

    G_DbgBlockHooked = TRUE;
    LogMessage("DbgBlock: installed OK (handler=%p).\n", G_DbgBlockHandler);
    return STATUS_SUCCESS;
}

static NTSTATUS DbgBlockRemove(VOID)
{
    if (!G_DbgBlockHooked) {
        G_DbgBlockActive = 0;
        LogMessage("DbgBlock: not installed.\n");
        return STATUS_SUCCESS;
    }

    G_DbgBlockHooked = FALSE;

    if (!NT_SUCCESS(DbgBlockWriteSafe(G_DbgBlockTarget, G_DbgBlockSaved, DBGBLOCK_SAVE_SIZE))) {
        LogMessage("DbgBlock: restore FAILED, hook may still be active.\n");
        G_DbgBlockHooked = TRUE;
        return STATUS_UNSUCCESSFUL;
    }
    LogMessage("DbgBlock: original bytes restored (%lu bytes).\n", DBGBLOCK_SAVE_SIZE);

    G_DbgBlockActive = 0;
    LogMessage("DbgBlock: removed.\n");
    return STATUS_SUCCESS;
}

static BOOLEAN DbgBlockIsActive(VOID)
{
    return G_DbgBlockHooked && G_DbgBlockActive != 0;
}
