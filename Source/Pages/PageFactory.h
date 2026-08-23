#pragma once

#include "AccountPage.h"
#include "CallbackPage.h"
#include "ChatPage.h"
#include "ConsolePage.h"
#include "DiskPage.h"
#include "DriverPage.h"
#include "FilePage.h"
#include "HandleLabPage.h"
#include "HookLabPage.h"
#include "KernelInspectorPage.h"
#include "KernelResearchPage.h"
#include "MemoryPage.h"
#include "ModuleManagerPage.h"
#include "ModuleRunPage.h"
#include "MonitorPage.h"
#include "PayloadPage.h"
#include "RegistryPage.h"
#include "ServicePage.h"
#include "SettingsPage.h"
#include "SnapshotLabPage.h"
#include "TablePage.h"
#include "TaskManagerPage.h"
#include "WindowPage.h"

class QWidget;

QWidget *CreateInformationPage();

QWidget *CreatePageBody(int Index);
