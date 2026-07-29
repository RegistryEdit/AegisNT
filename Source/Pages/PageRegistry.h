#pragma once

#include <QFluent/FluentIcon.h>

#include <array>

namespace AegisNT {

struct PageDefinition {
  const char *Title;
  const char *Subtitle;
  Fluent::IconType Icon;
};

const std::array<PageDefinition, 18> &PageDefinitions();

} // namespace AegisNT
