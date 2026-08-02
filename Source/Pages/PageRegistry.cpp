#include "PageRegistry.h"

namespace AegisNT {

const std::array<PageDefinition, 20> &PageDefinitions() {
  static constexpr std::array<PageDefinition, 20> Pages{{
      {"Information",
       "Application overview, environment status, and system information.",
       Fluent::IconType::INFO},
      {"Task", "Monitor system tasks in real-time.", Fluent::IconType::PEOPLE},
      {"Monitor", "System and process activity monitoring.",
       Fluent::IconType::VIEW},
      {"Registry", "Registry protection and management.",
       Fluent::IconType::CODE},
      {"File", "File protection and management.", Fluent::IconType::DOCUMENT},
      {"Window", "Window enumeration and management.",
       Fluent::IconType::BACK_TO_WINDOW},
      {"Driver", "Kernel driver enumeration and service control.",
       Fluent::IconType::DEVELOPER_TOOLS},
      {"Memory", "Read and write process memory through the kernel driver.",
       Fluent::IconType::TILES},
      {"Table", "Inspect kernel system table addresses and timing data.",
       Fluent::IconType::LAYOUT},
      {"Callback", "View and manage callback function registrations.",
       Fluent::IconType::SYNC},
      {"Payload", "Payload generation and reverse shell tools.",
       Fluent::IconType::SEND},
      {"ModuleRun", "Configure and execute runtime modules.",
       Fluent::IconType::PLAY},
      {"ModuleManager", "Manage installed modules and dependencies.",
       Fluent::IconType::LIBRARY},
      {"Console", "Integrated command-line console for debugging.",
       Fluent::IconType::COMMAND_PROMPT},
      {"Settings", "Application settings and configuration options.",
       Fluent::IconType::SETTING},
      {"KernelInspector",
       "Inspect kernel memory, objects, filters, networking, and security "
       "state.",
       Fluent::IconType::SEARCH},
      {"ServiceManager", "Windows services and kernel driver management.",
       Fluent::IconType::DEVELOPER_TOOLS},
      {"HandleLab",
       "Enumerate, correlate, and operate on system handles across processes.",
       Fluent::IconType::LINK},
      {"SnapshotLab",
       "Capture, persist, and compare process, driver, and callback snapshots.",
       Fluent::IconType::SEARCH},
      {"Disk", "DiskDrv protection, blocked events, and one-shot allow tokens.",
       Fluent::IconType::SAVE},
  }};
  return Pages;
}

} // namespace AegisNT
