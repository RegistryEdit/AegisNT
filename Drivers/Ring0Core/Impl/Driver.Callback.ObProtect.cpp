
static BOOLEAN G_InjectionInterceptorEnabled = TRUE;

static VOID
LogInjectionBlocked(
	_In_ HANDLE SourcePid,
	_In_ HANDLE TargetPid,
	_In_ ACCESS_MASK OriginalAccess
)
{
	LogMessage("Injection blocked: PID %u attempting 0x%08X access to PID %u.\n",
		HandleToULong(SourcePid), (ULONG)OriginalAccess, HandleToULong(TargetPid));
}

static ACCESS_MASK
StripProcessAccess(
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ACCESS_MASK OriginalAccess,
	_In_ HANDLE SourcePid,
	_In_ HANDLE TargetPid
)
{
	ACCESS_MASK InjectionMask = DesiredAccess & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);
	if ((InjectionMask & PROCESS_VM_WRITE) && (InjectionMask & PROCESS_CREATE_THREAD))
	{
		LogInjectionBlocked(SourcePid, TargetPid, OriginalAccess);
	}

	ACCESS_MASK SafeAccess = DesiredAccess & ~(
		PROCESS_TERMINATE              |
		PROCESS_CREATE_THREAD          |
		PROCESS_CREATE_PROCESS         |
		PROCESS_VM_OPERATION           |
		PROCESS_VM_READ                |
		PROCESS_VM_WRITE               |
		PROCESS_DUP_HANDLE             |
		PROCESS_SET_INFORMATION        |
		PROCESS_SET_PORT               |
		PROCESS_DEBUG_PORT             |
		PROCESS_THREAD_TERMINATE       |
		PROCESS_SET_LIMITED_INFORMATION);

	return SafeAccess;
}

static ACCESS_MASK
StripThreadAccess(
	_In_ ACCESS_MASK DesiredAccess
)
{
	ACCESS_MASK SafeAccess = DesiredAccess & ~(
		THREAD_TERMINATE              |
		THREAD_SUSPEND_RESUME         |
		THREAD_GET_CONTEXT            |
		THREAD_SET_CONTEXT            |
		THREAD_SET_INFORMATION        |
		THREAD_QUERY_INFORMATION      |
		THREAD_SET_LIMITED_INFORMATION |
		THREAD_DIRECT_IMPERSONATION);

	return SafeAccess;
}

static BOOLEAN
StripDangerousProcessAccess(
	_Inout_ POB_PRE_OPERATION_INFORMATION Info
)
{
	if (Info->KernelHandle)
		return FALSE;

	PEPROCESS TargetProcess = (PEPROCESS)Info->Object;
	HANDLE TargetPid = PsGetProcessId(TargetProcess);
	if (TargetPid == NULL) return FALSE;
	if (!IsProcessProtected(TargetPid) && !IsInjectionProtected(TargetPid)) return FALSE;

	HANDLE SourcePid = PsGetCurrentProcessId();
	ACCESS_MASK OriginalAccess;

	if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		ACCESS_MASK DesiredAccess = Info->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalAccess = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		ACCESS_MASK SafeAccess = StripProcessAccess(DesiredAccess, OriginalAccess, SourcePid, TargetPid);
		if (SafeAccess != DesiredAccess)
		{
			Info->Parameters->CreateHandleInformation.DesiredAccess = SafeAccess;
			return TRUE;
		}
	}
	else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		ACCESS_MASK DesiredAccess = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
		OriginalAccess = Info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		ACCESS_MASK SafeAccess = StripProcessAccess(DesiredAccess, OriginalAccess, SourcePid, TargetPid);
		if (SafeAccess != DesiredAccess)
		{
			Info->Parameters->DuplicateHandleInformation.DesiredAccess = SafeAccess;
			return TRUE;
		}
	}

	return FALSE;
}

static BOOLEAN
StripDangerousThreadAccess(
	_Inout_ POB_PRE_OPERATION_INFORMATION Info
)
{
	if (Info->KernelHandle) return FALSE;

	PETHREAD TargetThread = (PETHREAD)Info->Object;
	PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
	if (!TargetProcess) return FALSE;

	HANDLE TargetPid = PsGetProcessId(TargetProcess);
	if (TargetPid == NULL) return FALSE;
	if (!IsProcessProtected(TargetPid) && !IsInjectionProtected(TargetPid)) return FALSE;

	if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		ACCESS_MASK DesiredAccess = Info->Parameters->CreateHandleInformation.DesiredAccess;
		ACCESS_MASK SafeAccess = StripThreadAccess(DesiredAccess);
		if (SafeAccess != DesiredAccess)
		{
			Info->Parameters->CreateHandleInformation.DesiredAccess = SafeAccess;
			return TRUE;
		}
	}
	else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		ACCESS_MASK DesiredAccess = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
		ACCESS_MASK SafeAccess = StripThreadAccess(DesiredAccess);
		if (SafeAccess != DesiredAccess)
		{
			Info->Parameters->DuplicateHandleInformation.DesiredAccess = SafeAccess;
			return TRUE;
		}
	}

	return FALSE;
}
