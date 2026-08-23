
NTSTATUS
FirewallOperation(
	_In_ PFIREWALL_OPERATION_INPUT Input
)
{
	UNREFERENCED_PARAMETER(Input);
	LogMessage("Firewall: kernel-level WFP operations require fwpkclnt.lib linkage.\n");
	return STATUS_NOT_IMPLEMENTED;
}
