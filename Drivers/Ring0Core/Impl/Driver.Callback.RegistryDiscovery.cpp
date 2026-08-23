
NTSTATUS
FindCmCallbackListHead(
	_Out_ PLIST_ENTRY* ListHead
)
{
	*ListHead = NULL;

	UNICODE_STRING FuncName;
	RtlInitUnicodeString(&FuncName, L"CmRegisterCallbackEx");
	PUCHAR FuncStart = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);
	if (FuncStart == NULL)
	{
		LogMessage("FindCmCallbackListHead: CmRegisterCallbackEx not found\n");
		return STATUS_NOT_FOUND;
	}

	for (ULONG i = 0; i < 0x400; i++)
	{
		if (FuncStart[i] == 0x48 && FuncStart[i + 1] == 0x8D)
		{
			UCHAR RegEnc = FuncStart[i + 2];

			if ((RegEnc & 0xC7) == 0x05)
			{
				LONG  Disp = *(PLONG)(FuncStart + i + 3);
				PLIST_ENTRY Candidate = (PLIST_ENTRY)(FuncStart + i + 7 + Disp);

				__try
				{
					if ((ULONG_PTR)Candidate < 0xFFFF000000000000ULL)
						continue;
					if ((ULONG_PTR)Candidate->Flink < 0xFFFF000000000000ULL)
						continue;
					if ((ULONG_PTR)Candidate->Blink < 0xFFFF000000000000ULL)
						continue;

					if (Candidate->Flink != Candidate)
					{
						PUCHAR Entry = (PUCHAR)Candidate->Flink;
						PVOID  Func = *(PVOID*)(Entry + 0x28);
						if (Func == NULL || (ULONG_PTR)Func < 0xFFFF000000000000ULL)
							continue;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					continue;
				}

				*ListHead = Candidate;
				LogMessage("Found CmCallbackListHead at 0x%p\n", Candidate);
				return STATUS_SUCCESS;
			}
		}

		if (FuncStart[i] == 0x4C && FuncStart[i + 1] == 0x8D)
		{
			UCHAR RegEnc = FuncStart[i + 2];

			if ((RegEnc & 0xC7) == 0x05)
			{
				LONG  Disp = *(PLONG)(FuncStart + i + 3);
				PLIST_ENTRY Candidate = (PLIST_ENTRY)(FuncStart + i + 7 + Disp);

				__try
				{
					if ((ULONG_PTR)Candidate < 0xFFFF000000000000ULL)
						continue;
					if ((ULONG_PTR)Candidate->Flink < 0xFFFF000000000000ULL)
						continue;
					if ((ULONG_PTR)Candidate->Blink < 0xFFFF000000000000ULL)
						continue;

					if (Candidate->Flink != Candidate)
					{
						PUCHAR Entry = (PUCHAR)Candidate->Flink;
						PVOID  Func = *(PVOID*)(Entry + 0x28);
						if (Func == NULL || (ULONG_PTR)Func < 0xFFFF000000000000ULL)
							continue;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					continue;
				}

				*ListHead = Candidate;
				LogMessage("Found CmCallbackListHead at 0x%p (64-bit LEA)\n", Candidate);
				return STATUS_SUCCESS;
			}
		}
	}

	LogMessage("FindCmCallbackListHead: pattern not found\n");
	return STATUS_NOT_FOUND;
}
