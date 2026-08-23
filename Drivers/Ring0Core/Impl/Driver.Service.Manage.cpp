
NTSTATUS
ServiceOperation(
	_In_ PSERVICE_OPERATION_INPUT Input,
	_Out_writes_bytes_to_opt_(OutputLength, *BytesReturned) PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_Out_ PULONG BytesReturned
)
{
	*BytesReturned = 0;
	if (Input == NULL) return STATUS_INVALID_PARAMETER;
	Input->ServiceName[127] = L'\0';

	WCHAR RegPath[260];
	RtlStringCbPrintfW(RegPath, sizeof(RegPath),
		L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws", Input->ServiceName);

	UNICODE_STRING KeyName;
	RtlInitUnicodeString(&KeyName, RegPath);
	OBJECT_ATTRIBUTES Oa;
	InitializeObjectAttributes(&Oa, &KeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hKey = NULL;
	NTSTATUS Status;

	switch (Input->Operation)
	{
	case 0: 
	{
		if (Input->ServiceType == 1)
		{
			UNICODE_STRING DrvName;
			RtlInitUnicodeString(&DrvName, Input->ServiceName);
			Status = ZwLoadDriver(&DrvName);
			LogMessage("SvcOp: ZwLoadDriver(%ws) -> 0x%08X.\n", Input->ServiceName, Status);
			return Status;
		}
		Status = ZwOpenKey(&hKey, KEY_SET_VALUE, &Oa);
		if (!NT_SUCCESS(Status)) return Status;
		UNICODE_STRING Vn; RtlInitUnicodeString(&Vn, L"Start");
		ULONG StartType = 2; 
		Status = ZwSetValueKey(hKey, &Vn, 0, REG_DWORD, &StartType, sizeof(ULONG));
		ZwClose(hKey);
		return Status;
	}

	case 1: 
	{
		if (Input->ServiceType == 1)
		{
			UNICODE_STRING DrvName;
			RtlInitUnicodeString(&DrvName, Input->ServiceName);
			Status = ZwUnloadDriver(&DrvName);
			LogMessage("SvcOp: ZwUnloadDriver(%ws) -> 0x%08X.\n", Input->ServiceName, Status);
			return Status;
		}
		return STATUS_NOT_SUPPORTED;
	}

	case 2: 
	{
		Status = ZwOpenKey(&hKey, KEY_SET_VALUE, &Oa);
		if (!NT_SUCCESS(Status)) return Status;
		UNICODE_STRING Vn; RtlInitUnicodeString(&Vn, L"Start");
		ULONG StartType = 4; 
		Status = ZwSetValueKey(hKey, &Vn, 0, REG_DWORD, &StartType, sizeof(ULONG));
		ZwClose(hKey);
		return Status;
	}

	case 3: 
	{
		Status = ZwOpenKey(&hKey, KEY_SET_VALUE, &Oa);
		if (!NT_SUCCESS(Status)) return Status;
		UNICODE_STRING Vn; RtlInitUnicodeString(&Vn, L"Start");
		ULONG StartType = 2; 
		Status = ZwSetValueKey(hKey, &Vn, 0, REG_DWORD, &StartType, sizeof(ULONG));
		ZwClose(hKey);
		return Status;
	}

	case 4: 
	{
		Status = ZwOpenKey(&hKey, DELETE, &Oa);
		if (!NT_SUCCESS(Status)) return Status;
		Status = ZwDeleteKey(hKey);
		ZwClose(hKey);
		return Status;
	}

	case 5: 
	{
		Status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &Oa);
		if (!NT_SUCCESS(Status)) return Status;

		if (OutputBuffer && OutputLength >= (sizeof(ULONG) * 3 + sizeof(ULONG64)))
		{
			PULONG Out = (PULONG)OutputBuffer;
			ULONG ValSize = sizeof(ULONG);
			ULONG Val;
			UNICODE_STRING Vn;
			RtlInitUnicodeString(&Vn, L"Start");
			if (NT_SUCCESS(ZwQueryValueKey(hKey, &Vn, KeyValuePartialInformation, &Val, sizeof(Val), &ValSize)))
				Out[0] = Val; else Out[0] = 0xFFFFFFFF;
			RtlInitUnicodeString(&Vn, L"Type");
			if (NT_SUCCESS(ZwQueryValueKey(hKey, &Vn, KeyValuePartialInformation, &Val, sizeof(Val), &ValSize)))
				Out[1] = Val; else Out[1] = 0;
			RtlInitUnicodeString(&Vn, L"ErrorControl");
			if (NT_SUCCESS(ZwQueryValueKey(hKey, &Vn, KeyValuePartialInformation, &Val, sizeof(Val), &ValSize)))
				Out[2] = Val; else Out[2] = 0;
			*BytesReturned = sizeof(ULONG) * 3 + sizeof(ULONG64);
		}
		ZwClose(hKey);
		return Status;
	}
	}
	return STATUS_INVALID_PARAMETER;
}
