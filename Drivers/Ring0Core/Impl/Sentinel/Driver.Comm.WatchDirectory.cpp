static VOID NormalizeWatchDirectory(_Inout_updates_(260) PWCHAR DirectoryPath) {
    SIZE_T Length = 0;

    if (DirectoryPath == nullptr) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(DirectoryPath, 260, &Length))) {
        DirectoryPath[0] = L'\0';
        return;
    }

    while (Length > 1 &&
        (DirectoryPath[Length - 1] == L'\\' || DirectoryPath[Length - 1] == L'/')) {
        DirectoryPath[Length - 1] = L'\0';
        --Length;
    }
}

static NTSTATUS SetWatchDirectory(_In_reads_(260) const WCHAR* DirectoryPath) {
    WCHAR LocalPath[260] = {};
    NTSTATUS Status = STATUS_SUCCESS;

    if (DirectoryPath == nullptr || DirectoryPath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    Status = RtlStringCchCopyW(LocalPath, RTL_NUMBER_OF(LocalPath), DirectoryPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NormalizeWatchDirectory(LocalPath);
    if (LocalPath[0] != L'\\') {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&G_WatchLock);
    RtlStringCchCopyW(G_WatchedDirectory, RTL_NUMBER_OF(G_WatchedDirectory), LocalPath);
    G_WatchDirectoryActive = TRUE;
    ExReleaseFastMutex(&G_WatchLock);

    QueueClear(&G_FileQueue);
    DRV_INFO("Watching directory configured");
    return STATUS_SUCCESS;
}

static VOID ClearWatchDirectory() {
    ExAcquireFastMutex(&G_WatchLock);
    G_WatchedDirectory[0] = L'\0';
    G_WatchDirectoryActive = FALSE;
    ExReleaseFastMutex(&G_WatchLock);

    QueueClear(&G_FileQueue);
    DRV_INFO("Directory watch cleared");
}

static VOID QueryWatchDirectory(_Out_ MonitorWatchDirectoryOutput* Output) {
    RtlZeroMemory(Output, sizeof(*Output));

    ExAcquireFastMutex(&G_WatchLock);
    Output->Active = G_WatchDirectoryActive;
    if (G_WatchedDirectory[0] != L'\0') {
        RtlStringCchCopyW(Output->DirectoryPath, RTL_NUMBER_OF(Output->DirectoryPath), G_WatchedDirectory);
    }
    ExReleaseFastMutex(&G_WatchLock);
}

static BOOLEAN WatchDirectoryConfigured() {
    BOOLEAN Active = FALSE;
    ExAcquireFastMutex(&G_WatchLock);
    Active = G_WatchDirectoryActive;
    ExReleaseFastMutex(&G_WatchLock);
    return Active;
}
