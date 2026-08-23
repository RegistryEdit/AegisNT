
NTSTATUS
EnumerateSyncObjects(
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (OutputBuffer == NULL || OutputLength < sizeof(ULONG))
		return STATUS_BUFFER_TOO_SMALL;

	PULONG Count = (PULONG)OutputBuffer;
	*Count = 0;
	PUCHAR Data = (PUCHAR)(Count + 1);
	ULONG Remain = OutputLength - sizeof(ULONG);

	static const WCHAR* Directories[] = {
		L"\\BaseNamedObjects",
		NULL
	};

	for (ULONG d = 0; Directories[d] != NULL; d++)
	{
		UNICODE_STRING DirName;
		RtlInitUnicodeString(&DirName, Directories[d]);
		OBJECT_ATTRIBUTES Oa;
		InitializeObjectAttributes(&Oa, &DirName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hDir = NULL;
		if (!NT_SUCCESS(ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &Oa)))
			continue;

		ULONG Context = 0;
		BOOLEAN FirstCall = TRUE;

		while (Remain >= (260 + 16 + sizeof(ULONG) * 4))
		{
			UCHAR Buffer[4096];
			ULONG BufSize = sizeof(Buffer);
			NTSTATUS Status = ZwQueryDirectoryObject(hDir, Buffer, BufSize,
				FALSE, FirstCall, &Context, &BufSize);
			if (!NT_SUCCESS(Status)) break;
			FirstCall = FALSE;

			POBJECT_DIRECTORY_INFORMATION Info = (POBJECT_DIRECTORY_INFORMATION)Buffer;
			while (TRUE)
			{
				if (Remain < (260 + 16 + sizeof(ULONG) * 4)) break;

				if (Info->TypeName.Length > 0)
				{
					BOOLEAN Match = FALSE;
					if (_wcsnicmp(Info->TypeName.Buffer, L"Mutant", 6) == 0) Match = TRUE;
					else if (_wcsnicmp(Info->TypeName.Buffer, L"Event", 5) == 0) Match = TRUE;
					else if (_wcsnicmp(Info->TypeName.Buffer, L"Semaphore", 9) == 0) Match = TRUE;

					if (Match)
					{
						
						*(PULONG)Data = d; Data += 4;

						USHORT NLen = Info->Name.Length;
						if (NLen > 258) NLen = 258;
						*(PUSHORT)Data = NLen; Data += 2;
						if (Info->Name.Buffer && NLen > 0)
						{
							RtlCopyMemory(Data, Info->Name.Buffer, NLen);
							Data += NLen;
						}

						USHORT TLen = Info->TypeName.Length;
						if (TLen > 14) TLen = 14;
						*(PUSHORT)Data = TLen; Data += 2;
						if (Info->TypeName.Buffer && TLen > 0)
						{
							RtlCopyMemory(Data, Info->TypeName.Buffer, TLen);
							Data += TLen;
						}

						Data = (PUCHAR)(((ULONG_PTR)Data + 3) & ~3ULL);
						Remain = (ULONG)((PUCHAR)OutputBuffer + OutputLength - Data);
						(*Count)++;
					}
				}

				if (Info->Name.Length == 0 && Info->TypeName.Length == 0) break;
				Info = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)Info + sizeof(OBJECT_DIRECTORY_INFORMATION));
			}
		}
		ZwClose(hDir);
	}

	*BytesReturned = (ULONG)(Data - (PUCHAR)OutputBuffer);
	return STATUS_SUCCESS;
}
