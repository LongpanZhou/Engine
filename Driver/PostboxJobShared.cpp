// Job-only shared helpers.
//
// Included by main.cpp only for POSTBOX_JOB_ONLY builds. The job-only image has
// no Postbox channel, PBOX config, mailbox, timer, DPC, work item, NMI
// sanitizer, stack spoof, or reaper. This file supplies only:
//   - the job import typedefs used by PostboxJob.cpp
//   - PostboxStartFailure / PostboxWipe
//   - the PTE protection pass (loader pre-protects; no global IPI)
#ifdef POSTBOX_JOB_ONLY

#include "../Common/Postbox.h"

using FnPsLookupProcessByProcessId = int32_t (*)(void*, void**);
using FnObDereferenceObject = void (*)(void*);
using FnPsAcquireProcessExitSynchronization = int32_t (*)(void*);
using FnPsReleaseProcessExitSynchronization = void (*)(void*);
using FnPsGetProcessCreateTimeQuadPart = int64_t (*)(void*);
using FnPsGetCurrentProcess = void* (*)();
using FnMmCopyVirtualMemory = int32_t (*)(void* SourceProcess, void* SourceAddress,
                                          void* TargetProcess, void* TargetAddress,
                                          size_t Size, int32_t PreviousMode, size_t* Done);

uint32_t PostboxStartFailure = 0;

extern "C" _IMAGE_DOS_HEADER __ImageBase;

static void PostboxWipe(void* Data, size_t Size)
{
    if (!Data) return;
    volatile uint8_t* p = (volatile uint8_t*) Data;
    while (Size--) *p++ = 0;
}

static uint64_t* SelfMapEntry(address Va)
{
    const uint64_t PteBase = (uint64_t) GetPteBase();
    if (!PteBase) return nullptr;
    constexpr uint64_t Mask = (1ull << 39) - 8;
    return (uint64_t*) (uintptr_t) (PteBase + (((uint64_t) Va >> 9) & Mask));
}

static bool GetPteForVa(address Va, uint64_t*& Entry)
{
    uint64_t* Pte = SelfMapEntry(Va);
    if (!Pte) return false;
    uint64_t* Pde = SelfMapEntry(address((uint64_t) (uintptr_t) Pte));
    uint64_t* Pdpte = SelfMapEntry(address((uint64_t) (uintptr_t) Pde));
    uint64_t* Pml4e = SelfMapEntry(address((uint64_t) (uintptr_t) Pdpte));
    if (!Pml4e || !Pdpte || !Pde) return false;

    if (!(*Pml4e & 1) || !(*Pdpte & 1) || !(*Pde & 1)) return false;
    if (*Pdpte & (1ull << 7)) return false;       // 1 GB page
    if (*Pde & (1ull << 7)) return false;         // 2 MB page
    if (!(*Pte & 1)) return false;

    Entry = Pte;
    return true;
}

// Image protection verifier: the loader applied the final section map before
// the entry, so this pass only verifies the split on the entry CPU. It has no
// PostboxResolve, no PTE write, and no KeIpiGenericCall: the job image carries
// no export-name table and no global TLB IPI.
bool ProtectImageSectionsLayout(const PostboxImageLayout* Layout)
{
    PostboxStartFailure = 20;
    if (!Layout || Layout->Magic != PostboxLayoutMagic ||
        Layout->Version != PostboxLayoutVersion)
    {
        print(ERROR("PostboxJob: image layout missing or invalid"));
        return false;
    }

    const PostboxImageLayout& L = *Layout;
    if (L.ImageSize == 0 || L.AllocSize == 0 || L.SectionCount == 0 ||
        L.SectionCount > PostboxMaxSections || L.NtoskrnlBase == 0)
    {
        PostboxStartFailure = 21;
        return false;
    }

    constexpr uint64_t PostboxLayoutMaxBytes = 0x10000000;   // 256 MiB
    if (L.ImageSize > PostboxLayoutMaxBytes || L.AllocSize > PostboxLayoutMaxBytes ||
        L.ImageSize > L.AllocSize || L.RawBase + L.AllocSize < L.RawBase)
    {
        PostboxStartFailure = 24;
        return false;
    }

    MemSetPreStartNtoskrnl(L.NtoskrnlBase);

    const address ImageBase = address((uint64_t) (uintptr_t) &__ImageBase);
    if ((uint64_t) ImageBase != L.ImageBase || (L.ImageBase & 0xFFF) != 0)
    {
        print(ERROR("PostboxJob: image base mismatch (runtime %p, layout %p)"),
              (void*) (uintptr_t) ImageBase, (void*) (uintptr_t) L.ImageBase);
        PostboxStartFailure = 23;
        return false;
    }

    const uint64_t End = (L.RawBase + L.AllocSize) & ~0xFFFull;
    if (L.ImageBase < L.RawBase || L.ImageBase >= End ||
        L.ImageBase + L.ImageSize > End)
    {
        print(ERROR("PostboxJob: image layout range is invalid"));
        PostboxStartFailure = 24;
        return false;
    }

    for (uint64_t Va = L.ImageBase; Va < End; Va += 0x1000)
    {
        uint32_t Flags = PostboxPageRNx;
        const uint64_t PageEnd = Va + 0x1000;
        for (uint32_t i = 0; i < L.SectionCount; ++i)
        {
            const PostboxSectionLayout& S = L.Sections[i];
            const uint64_t SecStart = L.ImageBase + S.Rva;
            const uint64_t SecEnd = SecStart + S.Size;
            if (PageEnd <= (SecStart & ~0xFFFull) ||
                Va >= ((SecEnd + 0xFFF) & ~0xFFFull))
                continue;
            Flags = PostboxMergePageFlags(Flags, S.Flags);
        }

        const bool Write = (Flags == PostboxPageRwNx);
        const bool Execute = (Flags == PostboxPageRx);

        uint64_t* Verify = nullptr;
        if (!GetPteForVa(address(Va), Verify))
        {
            print(ERROR("PostboxJob: PTE verify walk failed at %p"), (void*) (uintptr_t) Va);
            PostboxStartFailure = 27;
            return false;
        }
        const uint64_t Pte = *Verify;
        const bool PteWrite = (Pte & 2) != 0;
        const bool PteNx = (Pte & (1ull << 63)) != 0;
        if (PteWrite != Write || PteNx == Execute)
        {
            print(ERROR("PostboxJob: PTE verify mismatch at %p (pte 0x%llX)"),
                  (void*) (uintptr_t) Va, (unsigned long long) Pte);
            PostboxStartFailure = 27;
            return false;
        }
    }

    print(INFO("PostboxJob: image protections verified (job-only)"));
    return true;
}

#endif // POSTBOX_JOB_ONLY
