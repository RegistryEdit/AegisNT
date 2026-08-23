#include <intrin.h>

typedef struct
{
    unsigned short Limit;
#ifdef _WIN64
    DWORD64 Base;
#else
    DWORD Base;
#endif
} GDTINFOS;

void ExecutePatchGuard()
{
    GDTINFOS IDT = {};
    __sidt(&IDT);
    const auto ELimit = IDT.Limit;
    IDT.Limit = 0xffff;
    __lidt(&IDT);
    __sidt(&IDT);
}