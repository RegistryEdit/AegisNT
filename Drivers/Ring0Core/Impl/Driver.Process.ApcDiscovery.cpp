
static NTSTATUS
FindKernelApcDisableOffset(
	_Out_ PULONG Offset
)
{
	*Offset = 0;

	RTL_OSVERSIONINFOW Version = {};
	Version.dwOSVersionInfoSize = sizeof(Version);

	NTSTATUS Status = RtlGetVersion(&Version);
	if (!NT_SUCCESS(Status))
	{
		LogMessage("FindKernelApcDisableOffset: RtlGetVersion failed: 0x%08X\n", Status);
		return Status;
	}

	if (Version.dwMajorVersion == 10 &&
		Version.dwMinorVersion == 0 &&
		Version.dwBuildNumber >= 19041 &&
		Version.dwBuildNumber <= 19045)
	{
		*Offset = 0x1E4;
		LogMessage("KernelApcDisable offset resolved for build %lu: 0x%lX\n",
			Version.dwBuildNumber, *Offset);
		return STATUS_SUCCESS;
	}

	LogMessage("KernelApcDisable offset unsupported on %lu.%lu build %lu.\n",
		Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber);
	return STATUS_NOT_SUPPORTED;
}
