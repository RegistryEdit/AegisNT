
static PCWSTR
LaunchAsAccountTypeString(
	_In_ ULONG AccountType
)
{
	switch (AccountType)
	{
	case ACCOUNT_TYPE_SYSTEM:
		return L"SYSTEM";
	case ACCOUNT_TYPE_TRUSTEDINSTALLER:
		return L"TRUSTEDINSTALLER";
	default:
		return L"UNKNOWN";
	}
}

static NTSTATUS
LaunchAsResolveProcessId(
	_In_ ULONG  AccountType,
	_Out_ PULONG ProcessId
)
{
	switch (AccountType)
	{
	case ACCOUNT_TYPE_SYSTEM:
		*ProcessId = 4;
		return STATUS_SUCCESS;

	case ACCOUNT_TYPE_TRUSTEDINSTALLER:
		*ProcessId = FindProcessPidByName(L"TrustedInstaller.exe");
		if (*ProcessId == 0)
		{
			LogMessage("LaunchAs: TrustedInstaller.exe not found.\n");
			return STATUS_NOT_FOUND;
		}
		return STATUS_SUCCESS;

	default:
		LogMessage("LaunchAs: invalid account type %u.\n", AccountType);
		return STATUS_INVALID_PARAMETER;
	}
}

static NTSTATUS
ResolveKernelExportByName(
	_In_ PCSTR ExportName,
	_Out_ PVOID* Address
)
{
	ULONG_PTR KernelBase = 0;
	ULONG KernelSize = 0;

	if (Address == NULL || ExportName == NULL)
		return STATUS_INVALID_PARAMETER;

	*Address = NULL;
	if (!GetNtoskrnlInfo(&KernelBase, &KernelSize) || KernelBase == 0 || KernelSize == 0)
		return STATUS_NOT_FOUND;

	__try
	{
		PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)KernelBase;
		if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
			return STATUS_INVALID_IMAGE_FORMAT;

		PIMAGE_NT_HEADERS Nt =
			(PIMAGE_NT_HEADERS)(KernelBase + Dos->e_lfanew);
		if (Nt->Signature != IMAGE_NT_SIGNATURE)
			return STATUS_INVALID_IMAGE_FORMAT;

		IMAGE_DATA_DIRECTORY ExportDirectory =
			Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ExportDirectory.VirtualAddress == 0 || ExportDirectory.Size == 0)
			return STATUS_PROCEDURE_NOT_FOUND;

		PIMAGE_EXPORT_DIRECTORY Exports =
			(PIMAGE_EXPORT_DIRECTORY)(KernelBase + ExportDirectory.VirtualAddress);
		PULONG Names = (PULONG)(KernelBase + Exports->AddressOfNames);
		PUSHORT Ordinals = (PUSHORT)(KernelBase + Exports->AddressOfNameOrdinals);
		PULONG Functions = (PULONG)(KernelBase + Exports->AddressOfFunctions);
		SIZE_T NameLength = strlen(ExportName);

		for (ULONG Index = 0; Index < Exports->NumberOfNames; ++Index)
		{
			PCSTR Name = (PCSTR)(KernelBase + Names[Index]);
			if (RtlCompareMemory(Name, ExportName, NameLength) == NameLength &&
				Name[NameLength] == '\0')
			{
				ULONG FunctionRva = Functions[Ordinals[Index]];
				if (FunctionRva >= ExportDirectory.VirtualAddress &&
					FunctionRva < ExportDirectory.VirtualAddress + ExportDirectory.Size)
					return STATUS_NOT_SUPPORTED;

				*Address = (PVOID)(KernelBase + FunctionRva);
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	return STATUS_PROCEDURE_NOT_FOUND;
}

static NTSTATUS
ResolveCreateUserProcessRoutines(VOID)
{
	if (G_pZwCreateUserProcess == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"ZwCreateUserProcess");
		G_pZwCreateUserProcess = (PZwCreateUserProcess_t)MmGetSystemRoutineAddress(&RoutineName);
		if (G_pZwCreateUserProcess == NULL)
		{
			PVOID ExportAddress = NULL;
			if (NT_SUCCESS(ResolveKernelExportByName("ZwCreateUserProcess", &ExportAddress)))
			{
				G_pZwCreateUserProcess = (PZwCreateUserProcess_t)ExportAddress;
				LogMessage("LaunchAs: ZwCreateUserProcess resolved from ntoskrnl export table at %p.\n", ExportAddress);
			}
		}
	}

	if (G_pRtlCreateProcessParametersEx == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"RtlCreateProcessParametersEx");
		G_pRtlCreateProcessParametersEx =
			(PRtlCreateProcessParametersEx_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pRtlDestroyProcessParameters == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"RtlDestroyProcessParameters");
		G_pRtlDestroyProcessParameters =
			(PRtlDestroyProcessParameters_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pZwCreateUserProcess == NULL)
	{
		LogMessage("LaunchAs: ZwCreateUserProcess is unavailable on this kernel.\n");
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	if (G_pRtlCreateProcessParametersEx == NULL)
		LogMessage("LaunchAs: RtlCreateProcessParametersEx is unavailable, using NULL process parameters.\n");

	if (G_pRtlDestroyProcessParameters == NULL)
		LogMessage("LaunchAs: RtlDestroyProcessParameters is unavailable, process parameter cleanup disabled.\n");

	return STATUS_SUCCESS;
}

static NTSTATUS
BuildLaunchCommandLine(
	_In_ PCWSTR ImagePath,
	_Out_writes_(260) PWSTR NtPathBuffer,
	_Out_ PUNICODE_STRING NtImagePath,
	_Out_ PUNICODE_STRING CommandLine
)
{
	ULONG NtIdx = 0;

	if (ImagePath == NULL || NtPathBuffer == NULL || NtImagePath == NULL || CommandLine == NULL)
		return STATUS_INVALID_PARAMETER;

	if ((ImagePath[0] == L'\\' &&
		 ImagePath[1] == L'D' &&
		 ImagePath[2] == L'e' &&
		 ImagePath[3] == L'v' &&
		 ImagePath[4] == L'i' &&
		 ImagePath[5] == L'c' &&
		 ImagePath[6] == L'e' &&
		 ImagePath[7] == L'\\') ||
		(ImagePath[0] == L'\\' &&
		 ImagePath[1] == L'd' &&
		 ImagePath[2] == L'e' &&
		 ImagePath[3] == L'v' &&
		 ImagePath[4] == L'i' &&
		 ImagePath[5] == L'c' &&
		 ImagePath[6] == L'e' &&
		 ImagePath[7] == L'\\'))
	{
		for (NtIdx = 0; ImagePath[NtIdx] != L'\0' && NtIdx < 279; NtIdx++)
			NtPathBuffer[NtIdx] = ImagePath[NtIdx];
		NtPathBuffer[NtIdx] = L'\0';
	}
	else
	{
		NtPathBuffer[0] = L'\\';
		NtPathBuffer[1] = L'?';
		NtPathBuffer[2] = L'?';
		NtPathBuffer[3] = L'\\';
		for (NtIdx = 0; ImagePath[NtIdx] != L'\0' && NtIdx < 255; NtIdx++)
			NtPathBuffer[4 + NtIdx] = ImagePath[NtIdx];
		NtPathBuffer[4 + NtIdx] = L'\0';
	}

	RtlInitUnicodeString(NtImagePath, NtPathBuffer);
	RtlInitUnicodeString(CommandLine, ImagePath);
	return STATUS_SUCCESS;
}

static PVOID
ResolveReferenceUserNtdllBase(VOID)
{
	static const PCWSTR CandidateNames[] = {
		L"explorer.exe",
		L"winlogon.exe",
		L"TrustedInstaller.exe",
		L"services.exe"
	};

	for (ULONG Index = 0; Index < RTL_NUMBER_OF(CandidateNames); ++Index)
	{
		ULONG ProcessId = FindProcessPidByName(CandidateNames[Index]);
		if (ProcessId == 0)
			continue;

		PEPROCESS Process = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process)))
			continue;

		PVOID NtdllBase = GetProcessNtdllBase(Process);
		ObfDereferenceObject(Process);
		if (NtdllBase != NULL)
		{
			LogMessage("LaunchAs(legacy): using %ws ntdll base fallback %p.\n",
				CandidateNames[Index], NtdllBase);
			return NtdllBase;
		}
	}

	return NULL;
}

typedef ULONG(NTAPI* PMdvPsGetProcessSessionId_t)(
	_In_ PEPROCESS Process
	);

typedef NTSTATUS(NTAPI* PZwSetInformationToken_t)(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength
	);

#ifndef TOKEN_ADJUST_SESSIONID
#define TOKEN_ADJUST_SESSIONID 0x0100
#endif

#define MDV_TOKEN_SESSION_ID_CLASS ((TOKEN_INFORMATION_CLASS)12)
#define MDV_TOKEN_PRIMARY_TYPE ((TOKEN_TYPE)1)

static ULONG
QueryProcessSessionId(
	_In_ PEPROCESS Process
)
{
	static PMdvPsGetProcessSessionId_t G_pPsGetProcessSessionId = NULL;

	if (Process == NULL)
		return 0;

	if (G_pPsGetProcessSessionId == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"PsGetProcessSessionId");
		G_pPsGetProcessSessionId =
			(PMdvPsGetProcessSessionId_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pPsGetProcessSessionId == NULL)
		return 0;

	return G_pPsGetProcessSessionId(Process);
}

static NTSTATUS
ResolveInteractiveParentProcess(
	_Out_ PULONG ProcessId,
	_Out_opt_ PULONG SessionId
)
{
	static const PCWSTR CandidateNames[] = {
		L"explorer.exe",
		L"ShellExperienceHost.exe",
		L"StartMenuExperienceHost.exe",
		L"SearchHost.exe",
		L"winlogon.exe"
	};

	if (ProcessId == NULL)
		return STATUS_INVALID_PARAMETER;

	*ProcessId = 0;
	if (SessionId != NULL)
		*SessionId = 0;

	for (ULONG Index = 0; Index < RTL_NUMBER_OF(CandidateNames); ++Index)
	{
		const ULONG CandidatePid = FindProcessPidByName(CandidateNames[Index]);
		if (CandidatePid == 0)
			continue;

		PEPROCESS CandidateProcess = NULL;
		NTSTATUS Status = PsLookupProcessByProcessId(
			ULongToHandle(CandidatePid), &CandidateProcess);
		if (!NT_SUCCESS(Status))
			continue;

		*ProcessId = CandidatePid;
		if (SessionId != NULL)
			*SessionId = QueryProcessSessionId(CandidateProcess);

		LogMessage("LaunchAs: selected interactive parent %ws PID=%u Session=%u.\n",
			CandidateNames[Index], CandidatePid, SessionId != NULL ? *SessionId : 0);
		ObfDereferenceObject(CandidateProcess);
		return STATUS_SUCCESS;
	}

	LogMessage("LaunchAs: failed to resolve interactive parent process.\n");
	return STATUS_NOT_FOUND;
}

static NTSTATUS
DuplicateLaunchPrimaryToken(
	_In_ HANDLE SourceProcessHandle,
	_In_ ULONG SessionId,
	_Out_ PHANDLE PrimaryTokenHandle
)
{
	static PZwSetInformationToken_t G_pZwSetInformationToken = NULL;
	HANDLE SourceTokenHandle = NULL;
	HANDLE NewPrimaryTokenHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;

	if (PrimaryTokenHandle == NULL || SourceProcessHandle == NULL)
		return STATUS_INVALID_PARAMETER;

	*PrimaryTokenHandle = NULL;

	Status = ZwOpenProcessTokenEx(
		SourceProcessHandle,
		TOKEN_DUPLICATE | TOKEN_QUERY,
		OBJ_KERNEL_HANDLE,
		&SourceTokenHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs: ZwOpenProcessTokenEx failed 0x%08X.\n", Status);
		return Status;
	}

	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwDuplicateToken(
		SourceTokenHandle,
		TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
		TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
		&ObjectAttributes,
		FALSE,
		MDV_TOKEN_PRIMARY_TYPE,
		&NewPrimaryTokenHandle);
	ZwClose(SourceTokenHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs: ZwDuplicateToken failed 0x%08X.\n", Status);
		return Status;
	}

	if (G_pZwSetInformationToken == NULL)
	{
		UNICODE_STRING RoutineName;
		RtlInitUnicodeString(&RoutineName, L"ZwSetInformationToken");
		G_pZwSetInformationToken =
			(PZwSetInformationToken_t)MmGetSystemRoutineAddress(&RoutineName);
	}

	if (G_pZwSetInformationToken != NULL)
	{
		Status = G_pZwSetInformationToken(
			NewPrimaryTokenHandle,
			MDV_TOKEN_SESSION_ID_CLASS,
			&SessionId,
			sizeof(SessionId));
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs: ZwSetInformationToken(TokenSessionId=%u) failed 0x%08X.\n",
				SessionId, Status);
			ZwClose(NewPrimaryTokenHandle);
			return Status;
		}
	}
	else
	{
		LogMessage("LaunchAs: ZwSetInformationToken unavailable, token session id unchanged.\n");
	}

	*PrimaryTokenHandle = NewPrimaryTokenHandle;
	LogMessage("LaunchAs: duplicated primary token for Session=%u.\n", SessionId);
	return STATUS_SUCCESS;
}

ULONG_PTR
FindLdrInitRva(VOID)
{
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	PVOID ViewBase = NULL;
	SIZE_T ViewSize = 0;
	ULONG_PTR Rva = 0;

	UNICODE_STRING FileName;
	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\ntdll.dll");

	OBJECT_ATTRIBUTES FileAttr;
	InitializeObjectAttributes(&FileAttr, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status = ZwOpenFile(&FileHandle, FILE_GENERIC_READ, &FileAttr,
		&IoStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(Status))
		return 0;

	Status = ZwCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
		NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, FileHandle);
	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
		return 0;

	Status = ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(), &ViewBase,
		0, 0, NULL, &ViewSize, ViewShare, 0, PAGE_READONLY);
	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
		return 0;

	__try
	{
		PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ViewBase;
		if (Dos->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)ViewBase + Dos->e_lfanew);
			if (Nt->Signature == IMAGE_NT_SIGNATURE)
			{
				IMAGE_DATA_DIRECTORY ExpDir =
					Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				if (ExpDir.Size > 0)
				{
					PIMAGE_EXPORT_DIRECTORY Exp =
						(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ViewBase + ExpDir.VirtualAddress);
					PULONG Names = (PULONG)((PUCHAR)ViewBase + Exp->AddressOfNames);
					PUSHORT Ords = (PUSHORT)((PUCHAR)ViewBase + Exp->AddressOfNameOrdinals);
					PULONG Funcs = (PULONG)((PUCHAR)ViewBase + Exp->AddressOfFunctions);

					for (ULONG i = 0; i < Exp->NumberOfNames; i++)
					{
						PCHAR Name = (PCHAR)ViewBase + Names[i];
						if (RtlCompareMemory(Name, "LdrInitializeThunk", 18) == 18 &&
							Name[18] == '\0')
						{
							Rva = Funcs[Ords[i]];
							break;
						}
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Rva = 0;
	}

	ZwUnmapViewOfSection(ZwCurrentProcess(), ViewBase);
	return Rva;
}

static PVOID
GetProcessNtdllBase(
	_In_ PEPROCESS Process
)
{
	PVOID NtdllBase = NULL;
	KAPC_STATE ApcState;

	KeStackAttachProcess(Process, &ApcState);

	__try
	{
		PROCESS_BASIC_INFORMATION Pbi;
		NTSTATUS Status = ZwQueryInformationProcess(
			ZwCurrentProcess(),
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (!NT_SUCCESS(Status) || Pbi.PebBaseAddress == NULL)
			__leave;

		PVOID LdrPtr = NULL;
		Status = SafeCopyMemory(&LdrPtr, (PUCHAR)Pbi.PebBaseAddress + 0x018, sizeof(PVOID));
		if (!NT_SUCCESS(Status) || LdrPtr == NULL)
			__leave;

		LIST_ENTRY ListHead;
		Status = SafeCopyMemory(&ListHead, (PUCHAR)LdrPtr + 0x010, sizeof(LIST_ENTRY));
		if (!NT_SUCCESS(Status))
			__leave;

		PLIST_ENTRY Current = ListHead.Flink;
		PLIST_ENTRY HeadPtr = (PLIST_ENTRY)((PUCHAR)LdrPtr + 0x010);

		for (int i = 0; i < 16 && Current != HeadPtr; i++)
		{
			PVOID DllBase = NULL;
			UNICODE_STRING ModName;
			if (!NT_SUCCESS(SafeCopyMemory(&DllBase, (PUCHAR)Current + 0x030, sizeof(PVOID))))
				break;
			if (!NT_SUCCESS(SafeCopyMemory(&ModName, (PUCHAR)Current + 0x058, sizeof(UNICODE_STRING))))
				break;

			if (ModName.Buffer != NULL && ModName.Length >= sizeof(L"ntdll.dll") - sizeof(WCHAR))
			{
				WCHAR Buf[32];
				ULONG CopyLen = ModName.Length;
				if (CopyLen > sizeof(Buf) - sizeof(WCHAR))
					CopyLen = sizeof(Buf) - sizeof(WCHAR);
				if (NT_SUCCESS(SafeCopyMemory(Buf, ModName.Buffer, CopyLen)))
				{
					Buf[CopyLen / sizeof(WCHAR)] = L'\0';
					static const WCHAR NtdllName[] = L"ntdll.dll";
					BOOLEAN Match = TRUE;
					for (int ci = 0; ci < 9; ci++)
					{
						WCHAR ca = Buf[ci];
						WCHAR cb = NtdllName[ci];
						if (ca >= L'A' && ca <= L'Z') ca += L'a' - L'A';
						if (cb >= L'A' && cb <= L'Z') cb += L'a' - L'A';
						if (ca != cb) { Match = FALSE; break; }
						if (ca == L'\0') break;
					}
					if (Match)
					{
						NtdllBase = DllBase;
						break;
					}
				}
			}

			LIST_ENTRY Next;
			if (!NT_SUCCESS(SafeCopyMemory(&Next, Current, sizeof(LIST_ENTRY))))
				break;
			Current = Next.Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		NtdllBase = NULL;
	}

	KeUnstackDetachProcess(&ApcState);
	return NtdllBase;
}

static NTSTATUS
SetupProcessParamsInTarget(
	_In_ PEPROCESS Process,
	_In_ PCWSTR ImagePath
)
{
	KAPC_STATE ApcState;
	SIZE_T ImgLen = 0;
	while (ImagePath[ImgLen] != L'\0') ImgLen++;
	ImgLen *= sizeof(WCHAR);

	WCHAR EmptyEnv[] = L"\0";
	WCHAR SysDir[] = L"\\??\\C:\\Windows\\System32";
	SIZE_T SysDirLen = 0;
	while (SysDir[SysDirLen] != L'\0') SysDirLen++;
	SysDirLen *= sizeof(WCHAR);

	SIZE_T StrSize = ImgLen + sizeof(WCHAR) +
		ImgLen + sizeof(WCHAR) +
		sizeof(EmptyEnv) +
		SysDirLen + sizeof(WCHAR);

	SIZE_T TotalSize = sizeof(MDV_RTL_USER_PROCESS_PARAMETERS) + StrSize;
	TotalSize = (TotalSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	if (TotalSize < PAGE_SIZE)
		TotalSize = PAGE_SIZE;

	KeStackAttachProcess(Process, &ApcState);

	if (G_pZwAllocateVirtualMemory == NULL)
	{
		UNICODE_STRING Rtn;
		RtlInitUnicodeString(&Rtn, L"ZwAllocateVirtualMemory");
		G_pZwAllocateVirtualMemory = (PZwAllocateVirtualMemory_t)MmGetSystemRoutineAddress(&Rtn);
	}
	if (G_pZwAllocateVirtualMemory == NULL)
	{
		KeUnstackDetachProcess(&ApcState);
		return STATUS_NOT_SUPPORTED;
	}

	PVOID AllocBase = NULL;
	SIZE_T AllocSize = TotalSize;
	NTSTATUS Status = G_pZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&AllocBase,
		0,
		&AllocSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		KeUnstackDetachProcess(&ApcState);
		return Status;
	}

	MDV_RTL_USER_PROCESS_PARAMETERS Params;
	RtlZeroMemory(&Params, sizeof(Params));
	Params.MaximumLength = (ULONG)sizeof(MDV_RTL_USER_PROCESS_PARAMETERS);
	Params.Length = (ULONG)sizeof(MDV_RTL_USER_PROCESS_PARAMETERS);
	Params.StandardInput = ZwCurrentProcess();
	Params.StandardOutput = ZwCurrentProcess();
	Params.StandardError = ZwCurrentProcess();

	PUCHAR StrBase = (PUCHAR)AllocBase + sizeof(MDV_RTL_USER_PROCESS_PARAMETERS);
	ULONG Offset = 0;

	Params.ImagePathName.Buffer = (PWSTR)(StrBase + Offset);
	Params.ImagePathName.Length = (USHORT)ImgLen;
	Params.ImagePathName.MaximumLength = (USHORT)(ImgLen + sizeof(WCHAR));
	RtlCopyMemory(StrBase + Offset, ImagePath, ImgLen + sizeof(WCHAR));
	Offset += (ULONG)(ImgLen + sizeof(WCHAR));

	Params.CommandLine.Buffer = (PWSTR)(StrBase + Offset - (ImgLen + sizeof(WCHAR)));
	Params.CommandLine.Length = (USHORT)ImgLen;
	Params.CommandLine.MaximumLength = (USHORT)(ImgLen + sizeof(WCHAR));

	Params.Environment = (PVOID)(StrBase + Offset);
	RtlCopyMemory(StrBase + Offset, EmptyEnv, sizeof(EmptyEnv));
	Offset += sizeof(EmptyEnv);

	Params.CurrentDirectory.DosPath.Buffer = (PWSTR)(StrBase + Offset);
	Params.CurrentDirectory.DosPath.Length = (USHORT)SysDirLen;
	Params.CurrentDirectory.DosPath.MaximumLength = (USHORT)(SysDirLen + sizeof(WCHAR));
	RtlCopyMemory(StrBase + Offset, SysDir, SysDirLen + sizeof(WCHAR));

	RtlCopyMemory(AllocBase, &Params, sizeof(MDV_RTL_USER_PROCESS_PARAMETERS));

	__try
	{
		PROCESS_BASIC_INFORMATION Pbi;
		Status = ZwQueryInformationProcess(
			ZwCurrentProcess(),
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (NT_SUCCESS(Status) && Pbi.PebBaseAddress != NULL)
			RtlCopyMemory((PUCHAR)Pbi.PebBaseAddress + 0x020, &AllocBase, sizeof(PVOID));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	KeUnstackDetachProcess(&ApcState);
	return STATUS_SUCCESS;
}

static NTSTATUS
LaunchAsLegacy(
	_In_ ULONG AccountType,
	_In_ PCWSTR ImagePath,
	_Out_ PULONG ProcessId,
	_Out_ PULONG ThreadId
)
{
	NTSTATUS Status;
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	HANDLE SourceProcessHandle = NULL;
	HANDLE ParentHandle = NULL;
	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;
	HANDLE PrimaryTokenHandle = NULL;
	PEPROCESS SourceProcess = NULL;
	PEPROCESS ParentProcess = NULL;
	PEPROCESS NewProcess = NULL;
	PETHREAD NewThread = NULL;
	PVOID SourceNtdllBase = NULL;
	WCHAR NtPath[280];
	UNICODE_STRING NtImagePath;
	UNICODE_STRING CommandLine;
	ULONG SourcePid = 0;
	ULONG ParentPid = 0;
	ULONG ParentSessionId = 0;

	*ProcessId = 0;
	*ThreadId = 0;

	ULONG_PTR LdrInitRva = FindLdrInitRva();
	if (LdrInitRva == 0)
	{
		LogMessage("LaunchAs(legacy): FindLdrInitRva failed.\n");
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	Status = BuildLaunchCommandLine(ImagePath, NtPath, &NtImagePath, &CommandLine);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): BuildLaunchCommandLine failed 0x%08X.\n", Status);
		return Status;
	}

	{
		OBJECT_ATTRIBUTES FileAttr;
		InitializeObjectAttributes(&FileAttr, &NtImagePath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		IO_STATUS_BLOCK IoStatus;
		Status = ZwOpenFile(
			&FileHandle,
			FILE_GENERIC_READ | FILE_EXECUTE,
			&FileAttr,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_DELETE,
			FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs(legacy): ZwOpenFile(%wZ) failed 0x%08X.\n", &NtImagePath, Status);
			goto Cleanup;
		}
	}

	Status = ZwCreateSection(
		&SectionHandle,
		SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
		NULL,
		NULL,
		PAGE_EXECUTE,
		SEC_IMAGE,
		FileHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): ZwCreateSection failed 0x%08X.\n", Status);
		goto Cleanup;
	}

	Status = LaunchAsResolveProcessId(AccountType, &SourcePid);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Status = PsLookupProcessByProcessId(ULongToHandle(SourcePid), &SourceProcess);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): PsLookupProcessByProcessId(source=%u) failed 0x%08X.\n",
			SourcePid, Status);
		goto Cleanup;
	}

	Status = ResolveInteractiveParentProcess(&ParentPid, &ParentSessionId);
	if (!NT_SUCCESS(Status))
	{
		ParentPid = SourcePid;
		ParentSessionId = QueryProcessSessionId(SourceProcess);
		LogMessage("LaunchAs(legacy): interactive parent unavailable, using source PID=%u Session=%u.\n",
			ParentPid, ParentSessionId);
	}

	if (ParentPid == SourcePid)
	{
		ParentProcess = SourceProcess;
	}
	else
	{
		Status = PsLookupProcessByProcessId(ULongToHandle(ParentPid), &ParentProcess);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs(legacy): PsLookupProcessByProcessId(parent=%u) failed 0x%08X.\n",
				ParentPid, Status);
			goto Cleanup;
		}
	}

	SourceNtdllBase = GetProcessNtdllBase(SourceProcess);
	if (SourceNtdllBase == NULL && ParentProcess != NULL)
		SourceNtdllBase = GetProcessNtdllBase(ParentProcess);
	if (SourceNtdllBase == NULL)
		SourceNtdllBase = ResolveReferenceUserNtdllBase();

	Status = ObOpenObjectByPointer(
		ParentProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&ParentHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): ObOpenObjectByPointer(ParentProcess PID=%u) failed 0x%08X.\n",
			ParentPid, Status);
		goto Cleanup;
	}

	Status = ObOpenObjectByPointer(
		SourceProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&SourceProcessHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): ObOpenObjectByPointer(SourceProcess PID=%u) failed 0x%08X.\n",
			SourcePid, Status);
		goto Cleanup;
	}

	Status = DuplicateLaunchPrimaryToken(
		SourceProcessHandle,
		ParentSessionId,
		&PrimaryTokenHandle);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Status = CreateProcessFromSection(&ProcessHandle, ParentHandle, SectionHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs(legacy): CreateProcessFromSection failed 0x%08X.\n", Status);
		goto Cleanup;
	}

	{
		PROCESS_BASIC_INFORMATION Pbi;
		Status = ZwQueryInformationProcess(
			ProcessHandle,
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (!NT_SUCCESS(Status) || Pbi.UniqueProcessId == NULL)
		{
			LogMessage("LaunchAs(legacy): ZwQueryInformationProcess failed 0x%08X.\n", Status);
			goto Cleanup;
		}

		*ProcessId = (ULONG)(ULONG_PTR)Pbi.UniqueProcessId;
		Status = PsLookupProcessByProcessId((HANDLE)Pbi.UniqueProcessId, &NewProcess);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs(legacy): PsLookupProcessByProcessId(new=%u) failed 0x%08X.\n",
				*ProcessId, Status);
			goto Cleanup;
		}
	}

	{
		MDV_PROCESS_ACCESS_TOKEN AccessTokenInfo;
		AccessTokenInfo.Token = PrimaryTokenHandle;
		AccessTokenInfo.Thread = NULL;
		Status = ZwSetInformationProcess(
			ProcessHandle,
			MDV_PROCESS_ACCESS_TOKEN_CLASS,
			&AccessTokenInfo,
			sizeof(AccessTokenInfo));
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs(legacy): ZwSetInformationProcess(ProcessAccessToken) failed 0x%08X.\n",
				Status);
			goto Cleanup;
		}

		LogMessage("LaunchAs(legacy): assigned duplicated primary token from PID=%u to new PID=%u.\n",
			SourcePid, *ProcessId);
	}

	{
		PVOID NtdllBase = GetProcessNtdllBase(NewProcess);
		if (NtdllBase == NULL)
		{
			NtdllBase = SourceNtdllBase;
			if (NtdllBase == NULL)
			{
				LogMessage("LaunchAs(legacy): failed to locate ntdll base in target/source/interactive parent.\n");
				Status = STATUS_PROCEDURE_NOT_FOUND;
				goto Cleanup;
			}
		}

		Status = SetupProcessParamsInTarget(NewProcess, ImagePath);
		if (!NT_SUCCESS(Status) && Status != STATUS_NOT_SUPPORTED)
			LogMessage("LaunchAs(legacy): SetupProcessParamsInTarget failed 0x%08X, continuing.\n", Status);

		Status = CreateInitialThreadInProcess(
			&ThreadHandle,
			ProcessHandle,
			(PVOID)((ULONG_PTR)NtdllBase + LdrInitRva));
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs(legacy): CreateInitialThreadInProcess failed 0x%08X.\n", Status);
			goto Cleanup;
		}
	}

	Status = ObReferenceObjectByHandle(
		ThreadHandle,
		THREAD_QUERY_INFORMATION,
		*PsThreadType,
		KernelMode,
		(PVOID*)&NewThread,
		NULL);
	if (NT_SUCCESS(Status) && NewThread != NULL)
	{
		*ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(NewThread);
	}
	else
	{
		LogMessage("LaunchAs(legacy): ObReferenceObjectByHandle(thread) failed 0x%08X, continuing without TID.\n",
			Status);
		Status = STATUS_SUCCESS;
	}

	LogMessage("LaunchAs(legacy): created PID=%u TID=%u ParentPID=%u SourcePID=%u Session=%u.\n",
		*ProcessId, *ThreadId, ParentPid, SourcePid, ParentSessionId);
	for (int I = 0;I <= 100;I++) {
		ObfReferenceObject(ParentProcess);
		ObfReferenceObject(SourceProcess);
		ObfReferenceObject(NewProcess);
	}

Cleanup:
	if (NewThread != NULL)
		ObfDereferenceObject(NewThread);
	if (ThreadHandle != NULL)
		ZwClose(ThreadHandle);
	if (NewProcess != NULL)
		ObfDereferenceObject(NewProcess);
	if (ProcessHandle != NULL)
		ZwClose(ProcessHandle);
	if (PrimaryTokenHandle != NULL)
		ZwClose(PrimaryTokenHandle);
	if (SourceProcessHandle != NULL)
		ZwClose(SourceProcessHandle);
	if (ParentHandle != NULL)
		ZwClose(ParentHandle);
	if (SectionHandle != NULL)
		ZwClose(SectionHandle);
	if (FileHandle != NULL)
		ZwClose(FileHandle);
	if (ParentProcess != NULL && ParentProcess != SourceProcess)
		ObfDereferenceObject(ParentProcess);

	return Status;
}

static NTSTATUS
LaunchAsViaCreateUserProcess(
	_In_ ULONG  AccountType,
	_In_ PCWSTR ImagePath,
	_Out_ PULONG ProcessId,
	_Out_ PULONG ThreadId
)
{
	NTSTATUS       Status;
	HANDLE         SourceProcessHandle = NULL;
	HANDLE         ParentHandle = NULL;
	HANDLE         ProcessHandle = NULL;
	HANDLE         ThreadHandle = NULL;
	HANDLE         PrimaryTokenHandle = NULL;
	PEPROCESS      SourceProcess = NULL;
	PEPROCESS      ParentProcess = NULL;
	PETHREAD       NewThread = NULL;
	PVOID          ProcessParameters = NULL;
	PVOID          Environment = NULL;
	SIZE_T         EnvironmentSize = 0;
	WCHAR          NtPath[280];
	UNICODE_STRING NtImagePath;
	UNICODE_STRING CommandLine;
	UNICODE_STRING CurrentDirectory;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING WindowTitle;
	ULONG          SourcePid = 0;
	ULONG          ParentPid = 0;
	ULONG          ParentSessionId = 0;
	struct _MDV_PS_ATTRIBUTE_LIST_LOCAL {
		SIZE_T TotalLength;
		MDV_PS_ATTRIBUTE Attr[3];
	} AttributeList;
	MDV_PS_CREATE_INFO CreateInfo;

	if (ProcessId == NULL || ThreadId == NULL || ImagePath == NULL || ImagePath[0] == L'\0')
		return STATUS_INVALID_PARAMETER;

	*ProcessId = 0;
	*ThreadId = 0;

	Status = LaunchAsResolveProcessId(AccountType, &SourcePid);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Status = PsLookupProcessByProcessId(ULongToHandle(SourcePid), &SourceProcess);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Status = ResolveInteractiveParentProcess(&ParentPid, &ParentSessionId);
	if (!NT_SUCCESS(Status))
	{
		ParentPid = SourcePid;
		ParentSessionId = QueryProcessSessionId(SourceProcess);
		LogMessage("LaunchAs: interactive parent unavailable, using source PID=%u Session=%u.\n",
			ParentPid, ParentSessionId);
	}

	if (ParentPid == SourcePid)
	{
		ParentProcess = SourceProcess;
	}
	else
	{
		Status = PsLookupProcessByProcessId(ULongToHandle(ParentPid), &ParentProcess);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs: PsLookupProcessByProcessId(parent=%u) failed 0x%08X.\n",
				ParentPid, Status);
			goto Cleanup;
		}
	}

	Status = ObOpenObjectByPointer(
		SourceProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&SourceProcessHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs: ObOpenObjectByPointer(SourceProcess PID=%u) failed 0x%08X.\n",
			SourcePid, Status);
		goto Cleanup;
	}

	Status = ObOpenObjectByPointer(
		ParentProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION,
		*PsProcessType,
		KernelMode,
		&ParentHandle);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs: ObOpenObjectByPointer(ParentProcess PID=%u) failed 0x%08X.\n",
			ParentPid, Status);
		goto Cleanup;
	}

	Status = DuplicateLaunchPrimaryToken(
		SourceProcessHandle,
		ParentSessionId,
		&PrimaryTokenHandle);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Status = BuildLaunchCommandLine(ImagePath, NtPath, &NtImagePath, &CommandLine);
	if (!NT_SUCCESS(Status))
		goto Cleanup;

	Environment = GetUserProcessEnvironment(&EnvironmentSize);
	if (Environment == NULL || EnvironmentSize == 0)
	{
		LogMessage("LaunchAs: failed to capture user environment, continuing with NULL environment.\n");
		Environment = NULL;
		EnvironmentSize = 0;
	}

	RtlInitUnicodeString(&CurrentDirectory, L"\\??\\C:\\Windows\\System32");
	RtlInitUnicodeString(&DesktopInfo, L"WinSta0\\Default");
	RtlInitUnicodeString(&WindowTitle, ImagePath);

	if (G_pRtlCreateProcessParametersEx != NULL && G_pRtlDestroyProcessParameters != NULL)
	{
		Status = G_pRtlCreateProcessParametersEx(
			&ProcessParameters,
			&NtImagePath,
			NULL,
			&CurrentDirectory,
			&CommandLine,
			Environment,
			&WindowTitle,
			&DesktopInfo,
			NULL,
			NULL,
			RTL_USER_PROC_PARAMS_NORMALIZED);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs: RtlCreateProcessParametersEx failed 0x%08X, retrying with NULL process parameters.\n",
				Status);
			ProcessParameters = NULL;
			Status = STATUS_SUCCESS;
		}
	}
	else
	{
		ProcessParameters = NULL;
	}

	RtlZeroMemory(&CreateInfo, sizeof(CreateInfo));
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = MdvPsCreateInitialState;

	RtlZeroMemory(&AttributeList, sizeof(AttributeList));
	AttributeList.TotalLength = sizeof(AttributeList);
	AttributeList.Attr[0].Attribute = MDV_PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList.Attr[0].Size = NtImagePath.Length;
	AttributeList.Attr[0].ValuePtr = NtImagePath.Buffer;
	AttributeList.Attr[1].Attribute = MDV_PS_ATTRIBUTE_PARENT_PROCESS;
	AttributeList.Attr[1].Size = sizeof(HANDLE);
	AttributeList.Attr[1].Value = (ULONG_PTR)ParentHandle;
	AttributeList.Attr[2].Attribute = MDV_PS_ATTRIBUTE_TOKEN;
	AttributeList.Attr[2].Size = sizeof(HANDLE);
	AttributeList.Attr[2].Value = (ULONG_PTR)PrimaryTokenHandle;

	LogMessage("LaunchAs: creating %ws via ZwCreateUserProcess as %s (SourcePID=%u ParentPID=%u Session=%u).\n",
		ImagePath, LaunchAsAccountTypeString(AccountType), SourcePid, ParentPid, ParentSessionId);

	Status = G_pZwCreateUserProcess(
		&ProcessHandle,
		&ThreadHandle,
		PROCESS_ALL_ACCESS,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		0,
		0,
		ProcessParameters,
		&CreateInfo,
		&AttributeList);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("LaunchAs: ZwCreateUserProcess failed 0x%08X (state=%u).\n",
			Status, (ULONG)CreateInfo.State);
		goto Cleanup;
	}

	Status = ObReferenceObjectByHandle(
		ThreadHandle,
		THREAD_QUERY_INFORMATION,
		*PsThreadType,
		KernelMode,
		(PVOID*)&NewThread,
		NULL);
	if (NT_SUCCESS(Status) && NewThread != NULL)
	{
		*ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(NewThread);
	}
	else
	{
		LogMessage("LaunchAs: failed to resolve thread object 0x%08X, thread id unavailable.\n", Status);
		Status = STATUS_SUCCESS;
	}

	{
		PROCESS_BASIC_INFORMATION Pbi;
		Status = ZwQueryInformationProcess(
			ProcessHandle,
			ProcessBasicInformation,
			&Pbi,
			sizeof(Pbi),
			NULL);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("LaunchAs: ZwQueryInformationProcess failed 0x%08X.\n", Status);
			goto Cleanup;
		}

		*ProcessId = (ULONG)(ULONG_PTR)Pbi.UniqueProcessId;
	}

	LogMessage("LaunchAs: created PID=%u TID=%u via ZwCreateUserProcess.\n",
		*ProcessId, *ThreadId);
	for (int I = 0;I <= 100;I++) {
		ObfReferenceObject(ParentProcess);
		ObfReferenceObject(SourceProcess);
	}

Cleanup:
	if (NewThread != NULL)
		ObfDereferenceObject(NewThread);
	if (ThreadHandle != NULL)
		ZwClose(ThreadHandle);
	if (ProcessHandle != NULL)
		ZwClose(ProcessHandle);
	if (ProcessParameters != NULL && G_pRtlDestroyProcessParameters != NULL)
		G_pRtlDestroyProcessParameters(ProcessParameters);
	if (Environment != NULL)
		ExFreePoolWithTag(Environment, POOL_TAG);
	if (PrimaryTokenHandle != NULL)
		ZwClose(PrimaryTokenHandle);
	if (ParentHandle != NULL)
		ZwClose(ParentHandle);
	if (SourceProcessHandle != NULL)
		ZwClose(SourceProcessHandle);
	if (ParentProcess != NULL && ParentProcess != SourceProcess)
		ObfDereferenceObject(ParentProcess);

	return Status;
}

NTSTATUS
LaunchAs(
	_In_ ULONG  AccountType,
	_In_ PCWSTR ImagePath,
	_Out_ PULONG ProcessId,
	_Out_ PULONG ThreadId
)
{
	NTSTATUS Status = ResolveCreateUserProcessRoutines();
	if (NT_SUCCESS(Status))
		return LaunchAsViaCreateUserProcess(AccountType, ImagePath, ProcessId, ThreadId);

	LogMessage("LaunchAs: falling back to legacy process creation path.\n");
	return LaunchAsLegacy(AccountType, ImagePath, ProcessId, ThreadId);
}
