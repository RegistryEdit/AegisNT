
NTSTATUS
FindObCallbackListOffset(
	_Out_ PULONG Offset
)
{
	*Offset = 0;

	POBJECT_TYPE ObjectTypes[2];
	ObjectTypes[0] = *PsProcessType;
	ObjectTypes[1] = *PsThreadType;

	#define DISKDRV_OB_IS_KERNEL_PTR(_ptr) \
	((ULONG_PTR)(_ptr) >= 0xFFFF800000000000ULL && (ULONG_PTR)(_ptr) <= 0xFFFFFFFFFFFF0000ULL)

	for (ULONG off = 0x80; off <= 0x300; off += sizeof(ULONG_PTR))
	{
		ULONG Matches = 0;

		for (INT t = 0; t < 2; t++)
		{
			PUCHAR      Base = (PUCHAR)ObjectTypes[t];
			PLIST_ENTRY ListHead = (PLIST_ENTRY)(Base + off);

			if (!MmIsAddressValid(ListHead))
				continue;
			if (!MmIsAddressValid(ListHead->Flink) ||
				!MmIsAddressValid(ListHead->Blink))
				continue;
			if (!DISKDRV_OB_IS_KERNEL_PTR(ListHead->Flink) ||
				!DISKDRV_OB_IS_KERNEL_PTR(ListHead->Blink))
				continue;

			if (ListHead->Flink == ListHead)
				continue;

			PUCHAR FirstEntry = (PUCHAR)ListHead->Flink;
			if (!MmIsAddressValid(FirstEntry + 0x30))
				continue;

			__try
			{
				POBJECT_TYPE EntryObjType = *(POBJECT_TYPE*)(FirstEntry + 0x20);
				PVOID        PreOp = *(PVOID*)(FirstEntry + 0x28);

				if (EntryObjType != ObjectTypes[t])
					continue;
				if (PreOp == NULL || !DISKDRV_OB_IS_KERNEL_PTR(PreOp))
					continue;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}

			Matches++;
		}

		if (Matches == 2)
		{
			*Offset = off;
			LogMessage("Found ObCallbackList at OBJECT_TYPE + 0x%X\n", off);
			return STATUS_SUCCESS;
		}
	}

	LogMessage("FindObCallbackListOffset: no match found\n");
	return STATUS_NOT_FOUND;
#undef DISKDRV_OB_IS_KERNEL_PTR
}
