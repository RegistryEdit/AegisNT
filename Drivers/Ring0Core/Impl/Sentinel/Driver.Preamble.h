#include "../../Driver.h"

static PDEVICE_OBJECT G_SentinelDeviceObject = nullptr;
static MONITOR_EVENT_QUEUE G_SystemQueue = {};
static MONITOR_EVENT_QUEUE G_FileQueue = {};
static MONITOR_EVENT_QUEUE G_NetworkQueue = {};
static MonitorFilterV2 G_MonitorFilter = { sizeof(MonitorFilterV2), MONITOR_PROTOCOL_VERSION, 0, 0, MAXULONG64, 0, {} };
static KSPIN_LOCK G_FilterLock;
static volatile LONG64 G_EventSequence = 0;
static FAST_MUTEX G_WatchLock;
static WCHAR G_WatchedDirectory[260] = {};
static BOOLEAN G_WatchDirectoryActive = FALSE;