
typedef struct _MDV_WINDOW_OFFSETS {
	BOOLEAN  Valid;
	ULONG_PTR Win32kBase;
	ULONG     Win32kSize;
	ULONG_PTR GSharedInfo;
	ULONG     HandleEntrySize;
	ULONG     HandleEntryCount;
	ULONG     HandleEntryPheadOffset;
	ULONG     TagWnd_DwStyle;
	ULONG     TagWnd_DwExStyle;
	ULONG     TagWnd_State;
	ULONG     TagWnd_State2;
	ULONG     TagWnd_RcWindow;
	ULONG     TagWnd_RcClient;
	ULONG     TagWnd_StrName;
	ULONG     TagWnd_IdProcess;
	ULONG     TagWnd_IdThread;
	ULONG     TagWnd_SpwndParent;
	ULONG     TagWnd_SpwndOwner;
	ULONG     TagWnd_SpwndChild;
	ULONG     TagWnd_SpwndNext;
	ULONG     TagWnd_Pcls;
	ULONG     TagWnd_LpfnWndProc;
	ULONG     TagWnd_Pti;
	ULONG     TagWnd_Spmenu;
	ULONG     TagWnd_CbWndExtra;
	ULONG     TagWnd_Pdesk;
} MDV_WINDOW_OFFSETS;

static MDV_WINDOW_OFFSETS G_WindowOffsets = { 0 };

static NTSTATUS
FindWin32kModule(
	_Out_ PULONG_PTR Base,
	_Out_ PULONG Size
)
{
	*Base = 0;
	*Size = 0;

	ULONG BufferSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)11, NULL, 0, &BufferSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		return Status;

	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)
		ExAllocatePool2(POOL_FLAG_NON_PAGED, BufferSize, POOL_TAG);
	if (Modules == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	Status = ZwQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)11, Modules, BufferSize, &BufferSize);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Modules, POOL_TAG);
		return Status;
	}

	for (ULONG i = 0; i < Modules->NumberOfModules; i++)
	{
		PRTL_PROCESS_MODULE_INFORMATION Mod = &Modules->Modules[i];
		if (Mod->ImageBase == NULL || Mod->ImageSize == 0)
			continue;

		PWCHAR Name = (PWCHAR)(Mod->FullPathName + Mod->OffsetToFileName);
		if (_wcsicmp(Name, L"win32k.sys") == 0 ||
			_wcsicmp(Name, L"win32kbase.sys") == 0 ||
			_wcsicmp(Name, L"win32kfull.sys") == 0)
		{
			*Base = (ULONG_PTR)Mod->ImageBase;
			*Size = Mod->ImageSize;
			break;
		}

		if (wcsstr((PWCHAR)Mod->FullPathName, L"win32k") != NULL ||
			wcsstr((PWCHAR)Mod->FullPathName, L"WIN32K") != NULL)
		{
			*Base = (ULONG_PTR)Mod->ImageBase;
			*Size = Mod->ImageSize;
			break;
		}
	}

	if (*Base == 0)
	{
		for (ULONG i = 0; i < Modules->NumberOfModules; i++)
		{
			PRTL_PROCESS_MODULE_INFORMATION Mod = &Modules->Modules[i];
			PWCHAR FilePart = (PWCHAR)(Mod->FullPathName + Mod->OffsetToFileName);
			if (_wcsnicmp(FilePart, L"win32k", 6) == 0)
			{
				*Base = (ULONG_PTR)Mod->ImageBase;
				*Size = Mod->ImageSize;
				break;
			}
		}
	}

	ExFreePoolWithTag(Modules, POOL_TAG);
	return *Base != 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static ULONG_PTR
ResolveWin32kExport(
	_In_ ULONG_PTR Win32kBase,
	_In_ PCCH ExportName
)
{
	if (Win32kBase == 0)
		return 0;

	__try
	{
		PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Win32kBase;
		if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		PIMAGE_NT_HEADERS64 Nt = (PIMAGE_NT_HEADERS64)(Win32kBase + Dos->e_lfanew);
		if (Nt->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		ULONG ExportRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (ExportRva == 0)
			return 0;

		PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)(Win32kBase + ExportRva);

		PULONG NameTable = (PULONG)(Win32kBase + Export->AddressOfNames);
		PUSHORT OrdinalTable = (PUSHORT)(Win32kBase + Export->AddressOfNameOrdinals);
		PULONG FuncTable = (PULONG)(Win32kBase + Export->AddressOfFunctions);

		for (ULONG i = 0; i < Export->NumberOfNames; i++)
		{
			PCCH Name = (PCCH)(Win32kBase + NameTable[i]);
			if (strcmp(Name, ExportName) == 0)
				return Win32kBase + FuncTable[OrdinalTable[i]];
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

static BOOLEAN
ScanForGSharedInfo(
	_In_ ULONG_PTR Win32kBase,
	_In_ ULONG Win32kSize,
	_Out_ PULONG_PTR GSharedInfoAddr
)
{
	*GSharedInfoAddr = 0;

	ULONG_PTR Exports[] = {
		ResolveWin32kExport(Win32kBase, "NtUserBuildHwndList"),
		ResolveWin32kExport(Win32kBase, "NtUserQueryWindow"),
		ResolveWin32kExport(Win32kBase, "NtUserFindWindowEx"),
		ResolveWin32kExport(Win32kBase, "NtUserCallOneParam"),
		ResolveWin32kExport(Win32kBase, "NtUserCallTwoParam"),
		ResolveWin32kExport(Win32kBase, "NtUserDestroyWindow"),
		ResolveWin32kExport(Win32kBase, "NtUserGetThreadState"),
		ResolveWin32kExport(Win32kBase, "NtUserSetWindowLong"),
		0
	};

	for (ULONG expIdx = 0; Exports[expIdx] != 0; expIdx++)
	{
		ULONG_PTR FnAddr = Exports[expIdx];
		if (FnAddr == 0)
			continue;

		for (ULONG off = 0; off < 256 - 6; off++)
		{
			PUCHAR Code = (PUCHAR)(FnAddr + off);

			if (Code[0] != 0x48) continue;
			if (Code[1] != 0x8D) continue;
			if (Code[2] != 0x0D && Code[2] != 0x15) continue;

			LONG RelDisp = *(PLONG)(Code + 3);
			ULONG_PTR Target = FnAddr + off + 7 + RelDisp;

			if (Target < Win32kBase || Target >= Win32kBase + Win32kSize)
				continue;

			__try
			{
				ULONG_PTR Candidate = *(volatile ULONG_PTR*)Target;
				if (Candidate >= Win32kBase && Candidate < Win32kBase + Win32kSize)
				{
					ULONG_PTR Second = *(volatile ULONG_PTR*)(Candidate + sizeof(ULONG_PTR));
					if (Second >= Win32kBase && Second < Win32kBase + Win32kSize)
					{
						ULONG_PTR Third = *(volatile ULONG_PTR*)(Candidate + 2 * sizeof(ULONG_PTR));
						if (Third > 0xFFFF000000000000ULL)
						{
							*GSharedInfoAddr = Target;
							return TRUE;
						}
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
		}
	}

	return FALSE;
}

static BOOLEAN
DiscoverHandleEntryLayout(
	_In_ ULONG_PTR GSharedInfo,
	_Out_ PULONG EntrySize,
	_Out_ PULONG EntryCount,
	_Out_ PULONG PheadOffset
)
{

	__try
	{
		ULONG_PTR Values[8];
		for (ULONG i = 0; i < 8; i++)
			Values[i] = *(volatile ULONG_PTR*)(GSharedInfo + i * sizeof(ULONG_PTR));

		ULONG_PTR aheList = 0;
		ULONG_PTR aheListEnd = 0;
		ULONG HeEntrySize = 0;

		for (ULONG i = 0; i < 7; i++)
		{
			if (Values[i] > 0xFFFF000000000000ULL &&
				Values[i + 1] > Values[i] &&
				Values[i + 1] - Values[i] >= 0x1000 &&
				Values[i + 1] - Values[i] <= 0x200000)
			{
				aheList = Values[i];
				aheListEnd = Values[i + 1];
				break;
			}
		}

		if (aheList == 0)
		{
			for (ULONG i = 2; i < 6; i++)
			{
				if (Values[i] > 0xFFFF000000000000ULL &&
					Values[i + 2] > Values[i] &&
					Values[i + 2] - Values[i] >= 0x1000 &&
					Values[i + 2] - Values[i] <= 0x200000)
				{
					aheList = Values[i];
					aheListEnd = Values[i + 2];
					break;
				}
			}
		}

		if (aheList == 0 || aheListEnd == 0)
			return FALSE;

		ULONG totalBytes = (ULONG)(aheListEnd - aheList);

		ULONG PossibleSizes[] = { 0x18, 0x20, 0x10, 0x28 };
		for (ULONG s = 0; s < 4; s++)
		{
			HeEntrySize = PossibleSizes[s];
			if (totalBytes % HeEntrySize == 0)
			{
				*EntryCount = totalBytes / HeEntrySize;
				if (*EntryCount >= 16 && *EntryCount <= 0x20000)
					break;
			}
			HeEntrySize = 0;
		}

		if (HeEntrySize == 0)
		{
			for (ULONG sz = 8; sz <= 64; sz += 8)
			{
				if (totalBytes % sz == 0)
				{
					ULONG cnt = totalBytes / sz;
					if (cnt >= 16 && cnt <= 0x20000)
					{
						HeEntrySize = sz;
						*EntryCount = cnt;
						break;
					}
				}
			}
		}

		if (HeEntrySize == 0)
			return FALSE;

		*EntrySize = HeEntrySize;

		*PheadOffset = 0;

		for (ULONG i = 0; i < 5; i++)
		{
			ULONG_PTR EntryAddr = aheList + i * HeEntrySize;
			ULONG_PTR Phead = *(volatile ULONG_PTR*)(EntryAddr + *PheadOffset);
			if (Phead != 0 && Phead < 0xFFFF000000000000ULL)
				return FALSE;
			if (Phead != 0)
			{
				return TRUE;
			}
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}

static BOOLEAN
DiscoverTagWndOffsets(
	_In_ ULONG_PTR Win32kBase,
	_In_ ULONG Win32kSize,
	_In_ ULONG_PTR GSharedInfo,
	_In_ ULONG HandleEntrySize,
	_In_ ULONG HandleEntryCount
)
{
	UNREFERENCED_PARAMETER(Win32kBase);
	UNREFERENCED_PARAMETER(Win32kSize);

	ULONG_PTR Values[8];
	ULONG_PTR aheList = 0;
	for (ULONG i = 0; i < 8; i++)
		Values[i] = *(volatile ULONG_PTR*)(GSharedInfo + i * sizeof(ULONG_PTR));

	for (ULONG i = 0; i < 7; i++)
	{
		if (Values[i] > 0xFFFF000000000000ULL &&
			Values[i + 1] > Values[i] &&
			Values[i + 1] - Values[i] >= 0x1000)
		{
			aheList = Values[i];
			break;
		}
	}

	if (aheList == 0)
		return FALSE;

	ULONG_PTR tagWnd = 0;
	for (ULONG i = 0; i < (HandleEntryCount < 500 ? HandleEntryCount : 500); i++)
	{
		ULONG_PTR Phead = *(volatile ULONG_PTR*)(aheList + i * HandleEntrySize);
		if (Phead > 0xFFFF000000000000ULL)
		{
			tagWnd = Phead;
			break;
		}
	}

	if (tagWnd == 0)
		return FALSE;

	ULONG idProcess = 0, idProcessOff = 0;
	ULONG idThread = 0, idThreadOff = 0;
	ULONG dwStyle = 0, dwStyleOff = 0;
	ULONG dwExStyle = 0, dwExStyleOff = 0;
	ULONG state = 0, stateOff = 0;

	for (ULONG off = 0; off < 0x300; off += 4)
	{
		__try
		{
			ULONG Val = *(volatile ULONG*)((PUCHAR)tagWnd + off);

			if (Val >= 4 && Val <= 0xFFFF && (Val % 4) == 0)
			{
				if (idProcessOff == 0 && off >= 0x80)
				{
					idProcess = Val;
					idProcessOff = off;
				}
			}

			if ((Val & 0xF0000000) != 0 && Val != 0xFFFFFFFF)
			{
				if (dwStyleOff == 0)
				{
					dwStyle = Val;
					dwStyleOff = off;
				}
			}

			if ((Val & 0xFF000000) != 0 && Val != 0xFFFFFFFF && off > dwStyleOff + 4)
			{
				if (dwExStyleOff == 0)
				{
					dwExStyle = Val;
					dwExStyleOff = off;
				}
			}

			if (Val >= 4 && Val <= 0xFFFF && (Val % 4) == 0 &&
				off > idProcessOff && off < idProcessOff + 0x20 && off != idProcessOff)
			{
				idThread = Val;
				idThreadOff = off;
			}

			if (Val != 0 && Val < 0x100000 && stateOff == 0 && off > 0x20)
			{
				state = Val;
				stateOff = off;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}

	if (idProcessOff == 0 || dwStyleOff == 0)
	{
		
		idProcessOff  = 0x2D8;
		idThreadOff   = 0x2DC;
		stateOff      = 0x100;
		dwStyleOff    = 0x110;
		dwExStyleOff  = 0x114;
	}

	G_WindowOffsets.Valid               = TRUE;
	G_WindowOffsets.GSharedInfo         = GSharedInfo;
	G_WindowOffsets.HandleEntrySize     = HandleEntrySize;
	G_WindowOffsets.HandleEntryCount    = HandleEntryCount;
	G_WindowOffsets.HandleEntryPheadOffset = 0;

	G_WindowOffsets.TagWnd_IdProcess    = idProcessOff;
	G_WindowOffsets.TagWnd_IdThread     = idThreadOff;
	G_WindowOffsets.TagWnd_DwStyle      = dwStyleOff;
	G_WindowOffsets.TagWnd_DwExStyle    = dwExStyleOff;
	G_WindowOffsets.TagWnd_State        = stateOff;
	G_WindowOffsets.TagWnd_State2       = stateOff + 4;

	G_WindowOffsets.TagWnd_RcWindow     = dwStyleOff > 0x200 ? 0x158 : 0xE8;
	G_WindowOffsets.TagWnd_RcClient     = dwStyleOff > 0x200 ? 0x168 : 0xF8;
	G_WindowOffsets.TagWnd_StrName      = 0xD8;
	G_WindowOffsets.TagWnd_SpwndParent  = 0x40;
	G_WindowOffsets.TagWnd_SpwndOwner   = 0x48;
	G_WindowOffsets.TagWnd_SpwndChild   = 0x30;
	G_WindowOffsets.TagWnd_SpwndNext    = 0x28;
	G_WindowOffsets.TagWnd_Pcls         = 0x68;
	G_WindowOffsets.TagWnd_LpfnWndProc  = 0x80;
	G_WindowOffsets.TagWnd_Pti          = 0x20;
	G_WindowOffsets.TagWnd_Spmenu       = 0x98;
	G_WindowOffsets.TagWnd_CbWndExtra   = 0xB4;
	G_WindowOffsets.TagWnd_Pdesk        = 0x20;

	return TRUE;
}

static BOOLEAN
EnsureWin32kOffsets(
	VOID
)
{
	if (G_WindowOffsets.Valid)
		return TRUE;

	ULONG_PTR Win32kBase = 0;
	ULONG Win32kSize = 0;
	NTSTATUS Status = FindWin32kModule(&Win32kBase, &Win32kSize);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("WindowEnum: cannot find win32k.sys (0x%08X).\n", Status);
		return FALSE;
	}

	G_WindowOffsets.Win32kBase = Win32kBase;
	G_WindowOffsets.Win32kSize = Win32kSize;
	LogMessage("WindowEnum: win32k base=0x%p size=0x%X.\n", (PVOID)Win32kBase, Win32kSize);

	ULONG_PTR GSharedInfo = 0;
	if (!ScanForGSharedInfo(Win32kBase, Win32kSize, &GSharedInfo))
	{
		LogMessage("WindowEnum: cannot locate gSharedInfo.\n");
		return FALSE;
	}

	LogMessage("WindowEnum: gSharedInfo at 0x%p (RVA 0x%X).\n",
		(PVOID)GSharedInfo, (ULONG)(GSharedInfo - Win32kBase));

	ULONG EntrySize = 0, EntryCount = 0, PheadOffset = 0;
	if (!DiscoverHandleEntryLayout(GSharedInfo, &EntrySize, &EntryCount, &PheadOffset))
	{
		LogMessage("WindowEnum: cannot discover handle entry layout.\n");
		return FALSE;
	}

	LogMessage("WindowEnum: handle entry size=0x%X count=%u.\n", EntrySize, EntryCount);

	return DiscoverTagWndOffsets(Win32kBase, Win32kSize, GSharedInfo, EntrySize, EntryCount);
}
