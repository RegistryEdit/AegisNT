
NTSTATUS
RegOperation(
	_In_ PREG_OPERATION_INPUT Input,
	_In_reads_bytes_(ExtraSize) PVOID ExtraData,
	_In_ ULONG ExtraSize,
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (Input == NULL)
		return STATUS_INVALID_PARAMETER;

	Input->KeyPath[259] = L'\0';
	Input->ValueName[127] = L'\0';

	UNICODE_STRING KeyName;
	RtlInitUnicodeString(&KeyName, Input->KeyPath);
	OBJECT_ATTRIBUTES Oa;
	InitializeObjectAttributes(&Oa, &KeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hKey = NULL;
	NTSTATUS Status = STATUS_SUCCESS;

	switch (Input->Operation)
	{
	case 0: 
	{
		Status = ZwOpenKey(&hKey, KEY_ENUMERATE_SUB_KEYS, &Oa);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("RegOp: ZwOpenKey(enum) failed 0x%08X for %ws.\n", Status, Input->KeyPath);
			return Status;
		}

		if (OutputBuffer == NULL || OutputLength < sizeof(ULONG) + 256)
		{ ZwClose(hKey); return STATUS_BUFFER_TOO_SMALL; }

		PULONG Count = (PULONG)OutputBuffer;
		*Count = 0;
		PUCHAR DataPtr = (PUCHAR)Count + sizeof(ULONG);
		ULONG Remaining = OutputLength - sizeof(ULONG);

		ULONG Index = 0;
		WCHAR NameBuf[256];
		ULONG NameLen;

		while (Remaining >= sizeof(WCHAR) * 2)
		{
			NameLen = sizeof(NameBuf) - sizeof(WCHAR);
			Status = ZwEnumerateKey(hKey, Index, KeyBasicInformation,
				NameBuf, RTL_NUMBER_OF(NameBuf) * sizeof(WCHAR), &NameLen);
			if (!NT_SUCCESS(Status))
				break;

			ULONG CopyLen = NameLen < Remaining ? NameLen : Remaining;
			RtlCopyMemory(DataPtr, NameBuf, CopyLen);
			CopyLen = (CopyLen + 1) & ~1u;
			DataPtr += CopyLen;
			Remaining -= CopyLen;
			(*Count)++;
			Index++;
		}

		*BytesReturned = (ULONG)(DataPtr - (PUCHAR)OutputBuffer);
		ZwClose(hKey);
		break;
	}

	case 1: 
	{
		Status = ZwOpenKey(&hKey, KEY_ENUMERATE_SUB_KEYS | DELETE, &Oa);
		if (!NT_SUCCESS(Status))
		{
			LogMessage("RegOp: ZwOpenKey(delete) failed 0x%08X.\n", Status);
			return Status;
		}

		ULONG Index = 0;
		WCHAR SubName[260];

		do
		{
			ULONG SubLen = sizeof(SubName) - sizeof(WCHAR);
			Status = ZwEnumerateKey(hKey, Index, KeyBasicInformation,
				SubName, sizeof(SubName) - sizeof(WCHAR), &SubLen);
			if (NT_SUCCESS(Status))
			{
				WCHAR FullSubPath[520];
				RtlStringCbPrintfW(FullSubPath, sizeof(FullSubPath), L"%ws\\%ws", Input->KeyPath, SubName);

				REG_OPERATION_INPUT SubInput = {};
				SubInput.Operation = 1;
				RtlStringCbCopyW(SubInput.KeyPath, sizeof(SubInput.KeyPath), FullSubPath);

				ULONG DummyReturned = 0;
				RegOperation(&SubInput, NULL, 0, NULL, 0, &DummyReturned);
				Index++;
			}
		} while (NT_SUCCESS(Status));

		ZwClose(hKey);

		Status = ZwOpenKey(&hKey, DELETE, &Oa);
		if (NT_SUCCESS(Status))
		{
			Status = ZwDeleteKey(hKey);
			ZwClose(hKey);
			LogMessage("RegOp: deleted key %ws (status 0x%08X).\n", Input->KeyPath, Status);
		}
		break;
	}

	case 2: 
	{
		Status = ZwOpenKey(&hKey, KEY_SET_VALUE, &Oa);
		if (!NT_SUCCESS(Status))
			return Status;

		UNICODE_STRING ValName;
		RtlInitUnicodeString(&ValName, Input->ValueName);
		Status = ZwSetValueKey(hKey, &ValName, 0, Input->ValueType,
			ExtraData, Input->ValueDataSize);
		ZwClose(hKey);
		LogMessage("RegOp: set value %ws on %ws (status 0x%08X).\n",
			Input->ValueName, Input->KeyPath, Status);
		break;
	}

	case 3: 
	{
		ULONG Disposition = 0;
		Status = ZwCreateKey(&hKey, KEY_READ | KEY_WRITE, &Oa, 0, NULL,
			REG_OPTION_NON_VOLATILE, &Disposition);
		if (NT_SUCCESS(Status) && hKey != NULL)
			ZwClose(hKey);
		LogMessage("RegOp: create key %ws (status 0x%08X).\n", Input->KeyPath, Status);
		break;
	}

	case 4: 
	{
		Status = ZwOpenKey(&hKey, KEY_SET_VALUE, &Oa);
		if (!NT_SUCCESS(Status))
			return Status;

		UNICODE_STRING ValName;
		RtlInitUnicodeString(&ValName, Input->ValueName);
		Status = ZwDeleteValueKey(hKey, &ValName);
		ZwClose(hKey);
		LogMessage("RegOp: deleted value %ws on %ws (status 0x%08X).\n",
			Input->ValueName, Input->KeyPath, Status);
		break;
	}

	default:
		return STATUS_INVALID_PARAMETER;
	}

	return Status;
}
