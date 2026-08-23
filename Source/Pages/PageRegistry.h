#pragma once

#include <QFluent/FluentIcon.h>

#include <array>

namespace AegisNT {

struct PageDefinition {
  const char *Title;
  const char *Subtitle;
  Fluent::IconType Icon;
};

const std::array<PageDefinition, 24> &PageDefinitions();

} // namespace AegisNT
