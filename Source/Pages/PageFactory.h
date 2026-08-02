#pragma once

class QWidget;

QWidget *CreateInformationPage();
QWidget *CreateTaskPage();
QWidget *CreateMonitorPage();
QWidget *CreateRegistryPage();
QWidget *CreateFilePage();
QWidget *CreateWindowPage();
QWidget *CreateDiskPage();
QWidget *CreateMemoryPage();
QWidget *CreateTablePage();
QWidget *CreateCallbackPage();
QWidget *CreatePayloadPage();
QWidget *CreateModuleRunPage();
QWidget *CreateConsolePage();
QWidget *CreateModuleManagerPage();
QWidget *CreateSettingsPage();
QWidget *CreateKernelInspectorPage();
QWidget *CreateDriverPage();
QWidget *CreateServiceManagerPage();
QWidget *CreateHandleLabPage();
QWidget *CreateSnapshotLabPage();

QWidget *CreatePageBody(int Index);
