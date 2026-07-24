#define AppName "AegisNT"
#define AppVersion "2.0.1"
#define AppPublisher "AegisNT"
#define AppExeName "AegisNT.exe"
#define SourceDir "C:\Users\RegistryEdit\Desktop\App\AegisNT"
#define DepDir "C:\Users\RegistryEdit\Desktop\App\AegisNT\Dep"
#define VcRedistFile "VC_redist.x64.exe"
#define NpcapFile "npcap-1.88.exe"
#define CertFile "CA_CERT.pem"
#define CertSubject "HttpCapture Root CA"
#define CertThumbprint "5CC18C3F3A60A4E2CEAD65606DDF2AE73D0F1BB2"

[Setup]
AppId={{A5B9EC4D-5173-4822-A11E-4850EB3A5FD8}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir=Output
OutputBaseFilename=AegisNT-Setup
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "Dep\*"
Source: "{#DepDir}\{#VcRedistFile}"; DestDir: "{tmp}"; Flags: deleteafterinstall ignoreversion
Source: "{#DepDir}\{#NpcapFile}"; DestDir: "{tmp}"; Flags: deleteafterinstall ignoreversion
Source: "{#SourceDir}\Data\{#CertFile}"; DestDir: "{tmp}"; Flags: deleteafterinstall ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"

[Code]
type
  TDependency = (depCertificate, depVcRuntime, depNpcap);

var
  DependencyPage: TWizardPage;
  DependencyChecks: array[0..2] of TNewCheckBox;
  DependencyStatus: array[0..2] of string;
  SummaryMemo: TNewMemo;

const
  StatusInstalled = 'Installed';
  StatusAlreadyInstalled = 'Already installed';
  StatusSkippedByUser = 'Skipped by user';
  StatusFailed = 'Failed';

function DependencyTitle(Dependency: TDependency): string;
begin
  case Dependency of
    depCertificate:
      Result := 'HTTP inspection certificate';
    depVcRuntime:
      Result := 'Microsoft VC++ Runtime';
    depNpcap:
      Result := 'Install Npcap';
  end;
end;

procedure SetDependencyStatus(Dependency: TDependency; const StatusText: string);
begin
  DependencyStatus[Ord(Dependency)] := StatusText;
  Log(Format('%s: %s', [DependencyTitle(Dependency), StatusText]));
end;

function IsDependencySelected(Dependency: TDependency): Boolean;
begin
  Result := Assigned(DependencyChecks[Ord(Dependency)]) and DependencyChecks[Ord(Dependency)].Checked;
end;

function IsVcRuntimeInstalled: Boolean;
var
  Installed: Cardinal;
begin
  Result :=
    RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and
    (Installed = 1);
end;

function IsNpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\npcap');
end;

function IsCertificateInstalled: Boolean;
var
  ResultCode: Integer;
  CmdLine: string;
begin
  CmdLine :=
    '/C certutil -user -store Root "' + ExpandConstant('{#CertSubject}') + '"' +
    ' | findstr /I /C:"' + ExpandConstant('{#CertThumbprint}') + '"';

  Result := Exec(ExpandConstant('{cmd}'), CmdLine, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and
    (ResultCode = 0);
end;

function RunDependencyInstaller(const FileName, Parameters: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(FileName, Parameters, '', SW_SHOW, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result then
  begin
    Log(Format('Execution failed for %s. ResultCode=%d', [FileName, ResultCode]));
  end;
end;

function InstallCertificate: Boolean;
begin
  Result := RunDependencyInstaller(
    ExpandConstant('{cmd}'),
    '/C certutil -user -f -addstore Root "' + ExpandConstant('{tmp}\{#CertFile}') + '"');
end;

function InstallVcRuntime: Boolean;
begin
  Result := RunDependencyInstaller(
    ExpandConstant('{tmp}\{#VcRedistFile}'),
    '/install /quiet /norestart');
end;

function InstallNpcap: Boolean;
begin
  Result := RunDependencyInstaller(
    ExpandConstant('{tmp}\{#NpcapFile}'),
    '/S');
end;

procedure UpdateSummaryMemo;
begin
  if not Assigned(SummaryMemo) then
    exit;

  SummaryMemo.Text :=
    'Optional Dependencies' + #13#10 + #13#10 +
    DependencyTitle(depCertificate) + ': ' + DependencyStatus[Ord(depCertificate)] + #13#10 +
    DependencyTitle(depVcRuntime) + ': ' + DependencyStatus[Ord(depVcRuntime)] + #13#10 +
    DependencyTitle(depNpcap) + ': ' + DependencyStatus[Ord(depNpcap)];
end;

procedure InitializeWizard;
var
  TopOffset: Integer;
begin
  DependencyPage := CreateCustomPage(
    wpSelectDir,
    'Optional Dependencies',
    'Select the optional dependencies to install.');

  TopOffset := ScaleY(8);

  DependencyChecks[Ord(depCertificate)] := TNewCheckBox.Create(WizardForm);
  DependencyChecks[Ord(depCertificate)].Parent := DependencyPage.Surface;
  DependencyChecks[Ord(depCertificate)].Left := 0;
  DependencyChecks[Ord(depCertificate)].Top := TopOffset;
  DependencyChecks[Ord(depCertificate)].Width := DependencyPage.SurfaceWidth;
  DependencyChecks[Ord(depCertificate)].Caption := 'Install HTTP inspection certificate';
  DependencyChecks[Ord(depCertificate)].Checked := True;

  TopOffset := TopOffset + ScaleY(24);

  DependencyChecks[Ord(depVcRuntime)] := TNewCheckBox.Create(WizardForm);
  DependencyChecks[Ord(depVcRuntime)].Parent := DependencyPage.Surface;
  DependencyChecks[Ord(depVcRuntime)].Left := 0;
  DependencyChecks[Ord(depVcRuntime)].Top := TopOffset;
  DependencyChecks[Ord(depVcRuntime)].Width := DependencyPage.SurfaceWidth;
  DependencyChecks[Ord(depVcRuntime)].Caption := 'Install Microsoft VC++ Runtime';
  DependencyChecks[Ord(depVcRuntime)].Checked := True;

  TopOffset := TopOffset + ScaleY(24);

  DependencyChecks[Ord(depNpcap)] := TNewCheckBox.Create(WizardForm);
  DependencyChecks[Ord(depNpcap)].Parent := DependencyPage.Surface;
  DependencyChecks[Ord(depNpcap)].Left := 0;
  DependencyChecks[Ord(depNpcap)].Top := TopOffset;
  DependencyChecks[Ord(depNpcap)].Width := DependencyPage.SurfaceWidth;
  DependencyChecks[Ord(depNpcap)].Caption := 'Install Npcap';
  DependencyChecks[Ord(depNpcap)].Checked := True;

  SummaryMemo := TNewMemo.Create(WizardForm);
  SummaryMemo.Parent := WizardForm.FinishedPage;
  SummaryMemo.Left := WizardForm.FinishedLabel.Left;
  SummaryMemo.Top := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height + ScaleY(12);
  SummaryMemo.Width := WizardForm.FinishedPage.Width - (WizardForm.FinishedLabel.Left * 2);
  SummaryMemo.Height := ScaleY(112);
  SummaryMemo.ReadOnly := True;
  SummaryMemo.WantReturns := False;
  SummaryMemo.ScrollBars := ssVertical;

  SetDependencyStatus(depCertificate, StatusSkippedByUser);
  SetDependencyStatus(depVcRuntime, StatusSkippedByUser);
  SetDependencyStatus(depNpcap, StatusSkippedByUser);
  UpdateSummaryMemo;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    exit;

  if IsDependencySelected(depCertificate) then
  begin
    if IsCertificateInstalled then
      SetDependencyStatus(depCertificate, StatusAlreadyInstalled)
    else if InstallCertificate then
      SetDependencyStatus(depCertificate, StatusInstalled)
    else
      SetDependencyStatus(depCertificate, StatusFailed);
  end
  else
    SetDependencyStatus(depCertificate, StatusSkippedByUser);

  if IsDependencySelected(depVcRuntime) then
  begin
    if IsVcRuntimeInstalled then
      SetDependencyStatus(depVcRuntime, StatusAlreadyInstalled)
    else if InstallVcRuntime then
      SetDependencyStatus(depVcRuntime, StatusInstalled)
    else
      SetDependencyStatus(depVcRuntime, StatusFailed);
  end
  else
    SetDependencyStatus(depVcRuntime, StatusSkippedByUser);

  if IsDependencySelected(depNpcap) then
  begin
    if IsNpcapInstalled then
      SetDependencyStatus(depNpcap, StatusAlreadyInstalled)
    else if InstallNpcap then
      SetDependencyStatus(depNpcap, StatusInstalled)
    else
      SetDependencyStatus(depNpcap, StatusFailed);
  end
  else
    SetDependencyStatus(depNpcap, StatusSkippedByUser);

  UpdateSummaryMemo;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
    UpdateSummaryMemo;
end;
