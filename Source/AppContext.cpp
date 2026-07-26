#include "AppContext.h"

namespace AegisNT
{

AppContext &ApplicationContext()
{
    static AppContext Context;
    return Context;
}

} // namespace AegisNT
