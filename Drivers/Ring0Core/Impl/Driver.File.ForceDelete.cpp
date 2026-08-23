
NTSTATUS
ForceDeleteFile(
	_In_ PCWSTR FilePath
)
{
	UNICODE_STRING    UniPath;
	OBJECT_ATTRIBUTES Oa;
	HANDLE            hFile;
	IO_STATUS_BLOCK   IoStatus;
	NTSTATUS          Status;
	NTSTATUS          DeleteStatus;

	RtlInitUnicodeString(&UniPath, FilePath);
	InitializeObjectAttributes(&Oa, &UniPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(
		&hFile,
		DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
		&Oa,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(Status))
	{
		LogMessage("ForceDeleteFile: ZwCreateFile failed 0x%08X for %ws.\n", Status, FilePath);
		return Status;
	}

	IO_STATUS_BLOCK     Iosb;
	FILE_STANDARD_INFORMATION Fsi;
	Status = ZwQueryInformationFile(hFile, &Iosb, &Fsi, sizeof(Fsi), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("ForceDeleteFile: ZwQueryInformationFile failed 0x%08X.\n", Status);
		ZwClose(hFile);
		return Status;
	}

	FILE_DISPOSITION_INFORMATION Fdi;
	Fdi.DeleteFile = TRUE;
	Status = ZwSetInformationFile(hFile, &Iosb, &Fdi, sizeof(Fdi), FileDispositionInformation);
	DeleteStatus = Status;
	if (NT_SUCCESS(Status))
		LogMessage("ForceDeleteFile: %ws marked for deletion.\n", FilePath);
	else
		LogMessage("ForceDeleteFile: mark failed 0x%08X, continuing.\n", Status);

	PFILE_OBJECT OurFileObj = NULL;
	Status = ObReferenceObjectByHandle(
		hFile, FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode,
		(PVOID*)&OurFileObj, NULL);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(hFile);
		return NT_SUCCESS(DeleteStatus) ? DeleteStatus : Status;
	}

	PVOID OurFsContext = OurFileObj->FsContext;

	ULONG BufSize = 0x100000; 
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = NULL;
	ULONG ClosedCount = 0;

	for (INT Retry = 0; Retry < 4; Retry++)
	{
		if (HandleInfo != NULL)
			ExFreePoolWithTag(HandleInfo, POOL_TAG);

		HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)
			ExAllocatePool2(POOL_FLAG_NON_PAGED, BufSize, POOL_TAG);
		if (HandleInfo == NULL)
			break;

		Status = ZwQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)64, 
			HandleInfo, BufSize, &BufSize);

		if (NT_SUCCESS(Status))
			break;

		BufSize *= 2;
		if (BufSize > 0x4000000) 
			break;
	}

	if (HandleInfo != NULL && NT_SUCCESS(Status))
	{
		for (ULONG_PTR i = 0; i < HandleInfo->NumberOfHandles; i++)
		{
			ULONG_PTR Pid = HandleInfo->Handles[i].UniqueProcessId;
			ULONG_PTR Hval = HandleInfo->Handles[i].HandleValue;

			if (Pid == 0 || Pid == 4)
				continue;

			if (Pid == (ULONG)(ULONG_PTR)PsGetCurrentProcessId())
				continue;

			PEPROCESS TargetProc = NULL;
			Status = PsLookupProcessByProcessId((HANDLE)Pid, &TargetProc);
			if (!NT_SUCCESS(Status))
				continue;

			HANDLE hTarget = NULL;
			Status = ObOpenObjectByPointer(
				TargetProc, OBJ_KERNEL_HANDLE, NULL,
				PROCESS_DUP_HANDLE, *PsProcessType, KernelMode, &hTarget);

			if (NT_SUCCESS(Status))
			{
				HANDLE hDup = NULL;
				Status = ZwDuplicateObject(
					hTarget,
					(HANDLE)Hval,
					ZwCurrentProcess(),
					&hDup,
					0, 0, DUPLICATE_SAME_ACCESS);

				if (NT_SUCCESS(Status) && hDup != NULL)
				{
					
					PFILE_OBJECT DupFileObj = NULL;
					NTSTATUS ObjStatus = ObReferenceObjectByHandle(
						hDup, 0, *IoFileObjectType, KernelMode,
						(PVOID*)&DupFileObj, NULL);

					if (NT_SUCCESS(ObjStatus) && DupFileObj != NULL)
					{
						if (DupFileObj->FsContext == OurFsContext)
						{
							
							ObfDereferenceObject(DupFileObj);

							ZwClose(hDup);
							hDup = NULL;

							Status = ZwDuplicateObject(
								hTarget,
								(HANDLE)Hval,
								ZwCurrentProcess(),
								&hDup,
								0, 0,
								DUPLICATE_CLOSE_SOURCE);

							if (NT_SUCCESS(Status))
							{
								ZwClose(hDup);
								ClosedCount++;
							}
						}
						else
						{
							ObfDereferenceObject(DupFileObj);
						}
					}

					if (hDup != NULL)
						ZwClose(hDup);
				}

				ZwClose(hTarget);
			}

			ObfDereferenceObject(TargetProc);
		}

		if (ClosedCount > 0)
			LogMessage("ForceDeleteFile: closed %u external handles.\n", ClosedCount);
	}

	ObfDereferenceObject(OurFileObj);

	if (HandleInfo != NULL)
		ExFreePoolWithTag(HandleInfo, POOL_TAG);

	Status = ZwSetInformationFile(hFile, &Iosb, &Fdi, sizeof(Fdi), FileDispositionInformation);
	if (NT_SUCCESS(Status))
		DeleteStatus = Status;
	else if (!NT_SUCCESS(DeleteStatus))
		DeleteStatus = Status;

	ZwClose(hFile);
	if (NT_SUCCESS(DeleteStatus))
		LogMessage("ForceDeleteFile: %ws done.\n", FilePath);
	else
		LogMessage("ForceDeleteFile: final mark failed 0x%08X for %ws.\n", DeleteStatus, FilePath);
	return DeleteStatus;
}
