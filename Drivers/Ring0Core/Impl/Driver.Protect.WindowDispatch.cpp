
NTSTATUS
AddWindowProtect(
	_In_ PWINDOW_PROTECT_INPUT Input
)
{
	if (Input == NULL || Input->Hwnd == 0)
		return STATUS_INVALID_PARAMETER;
	return AddWindowToProtectionList(Input->Hwnd, Input->ProcessId, Input->Flags ? Input->Flags : WINPROT_ALL);
}

NTSTATUS
RemoveWindowProtect(
	_In_ PWINDOW_PROTECT_INPUT Input
)
{
	if (Input == NULL || Input->Hwnd == 0)
		return STATUS_INVALID_PARAMETER;
	return RemoveWindowFromProtectionList(Input->Hwnd);
}

NTSTATUS
AddInjectionProtect(
	_In_ PINJECTION_PROTECT_INPUT Input
)
{
	if (Input == NULL || Input->ProcessId == 0)
		return STATUS_INVALID_PARAMETER;
	return AddInjectionProtection(Input->ProcessId);
}

NTSTATUS
RemoveInjectionProtect(
	_In_ PINJECTION_PROTECT_INPUT Input
)
{
	if (Input == NULL || Input->ProcessId == 0)
		return STATUS_INVALID_PARAMETER;
	return RemoveInjectionProtection(Input->ProcessId);
}
