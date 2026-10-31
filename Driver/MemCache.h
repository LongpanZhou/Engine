#pragma once
#include <cstdint>

// Cached kernel constants used by the memory layer. The Postbox build keeps
// them on the independent state page so the mapped image's .data carries no
// ntoskrnl-base or PTE-base pointer. Mem.cpp uses a transient static cache
// until the state page exists; MemAdoptCaches() then moves the values into the
// state page and zeroes the static slots.
struct PostboxMemCaches
{
    uint64_t Ntoskrnl;
    uint64_t PteBase;
    uint64_t PfnPteAddressBase;
};

#ifdef POSTBOX_CHANNEL
PostboxMemCaches* PostboxGetMemCaches();
#else
inline PostboxMemCaches* PostboxGetMemCaches() { return nullptr; }
#endif

// Copies the transient cache into Dst (when non-null) and clears the statics.
void MemAdoptCaches(PostboxMemCaches* Dst);
