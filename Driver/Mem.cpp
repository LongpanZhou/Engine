using namespace arch;
using namespace intrin;

enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB,
    Page_Unmap
};

// Claims an empty entry for a mapping. An entry is empty only when all of its bits are zero, so a claim never
// takes an entry that a live mapping still uses, or overwrites a non-present entry that holds other state
template<typename T>
bool ClaimEntry(T *Entry, T Value)
{
    uint64_t Expected = 0;
    uint64_t Desired;
    memcpy(&Desired, &Value, sizeof(Desired));
    return __atomic_compare_exchange_n((uint64_t *) Entry, &Expected, Desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

// Empties an entry again, so the next mapping can claim it
template<typename T>
void ReleaseEntry(T *Entry)
{
    __atomic_store_n((uint64_t *) Entry, 0, __ATOMIC_SEQ_CST);
}

// MapPhysicalToVirtual
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize = Page_4KB)
{
    // Local variables. They are per call, so concurrent callers never share mapping state
    int PML4_IDX, PDPT_IDX, PD_IDX, PT_IDX;
    cr3 CR3 = read_cr3();
    address tmp;
    address VA{};

    pml4e* PML4E;
    pdpe* PDPTE;
    pde* PDE;

    // PML4: the first present entry leads to the PDPT
    tmp = win::MmGetVirtualForPhysical({CR3.pml4_frame_number << 12});
    for (PML4_IDX = 0; PML4_IDX < 512; ++PML4_IDX)
    {
        PML4E = &((pml4e *)tmp)[PML4_IDX];
        if (PML4E->present) break;
    }
    if (PML4_IDX == 512) return false;

    // PDPT
    tmp = win::MmGetVirtualForPhysical({PML4E->page_frame_number << 12});
    for (PDPT_IDX = 0; PDPT_IDX < 512; ++PDPT_IDX)
    {
        PDPTE = &((pdpe *) tmp)[PDPT_IDX];
        if (PageSize == Page_1GB)
        {
            if (PDPTE->present) continue;

            pdpe_1gb Value{};
            Value.present = 1;
            Value.write = 1;
            Value.page_size = 1;
            Value.page_frame_number = PhysicalAddress >> 30;
            if (!ClaimEntry((pdpe_1gb *) PDPTE, Value)) continue;

            VA.offset = PhysicalAddress.offset;
            VA.p1_index = PhysicalAddress.p1_index;
            VA.p2_index = PhysicalAddress.p2_index;
            VA.p3_index = PDPT_IDX;
            VA.p4_index = PML4_IDX;

            Callback(VA);
            ReleaseEntry((pdpe_1gb *) PDPTE);
            return true;
        }

        // A 1GB entry maps memory directly and is not a table, so only a present, non-large entry leads to a PD
        if (PDPTE->present && !((pdpe_1gb *) PDPTE)->page_size) break;
    }
    if (PageSize == Page_1GB || PDPT_IDX == 512) return false;

    // PD
    tmp = win::MmGetVirtualForPhysical({PDPTE->page_frame_number << 12});
    for (PD_IDX = 0; PD_IDX < 512; ++PD_IDX)
    {
        PDE = &((pde *) tmp)[PD_IDX];
        if (PageSize == Page_2MB)
        {
            if (PDE->present) continue;

            pde_2mb Value{};
            Value.present = 1;
            Value.write = 1;
            Value.page_size = 1;
            Value.page_frame_number = PhysicalAddress >> 21;
            if (!ClaimEntry((pde_2mb *) PDE, Value)) continue;

            VA.offset = PhysicalAddress.offset;
            VA.p1_index = PhysicalAddress.p1_index;
            VA.p2_index = PD_IDX;
            VA.p3_index = PDPT_IDX;
            VA.p4_index = PML4_IDX;

            Callback(VA);
            ReleaseEntry((pde_2mb *) PDE);
            return true;
        }

        // Same rule as the PDPT: a 2MB entry is a mapping, not a page table
        if (PDE->present && !((pde_2mb *) PDE)->page_size) break;
    }
    if (PageSize == Page_2MB || PD_IDX == 512) return false;

    // PT
    tmp = win::MmGetVirtualForPhysical({PDE->page_frame_number << 12});
    for (PT_IDX = 0; PT_IDX < 512; ++PT_IDX)
    {
        pte *PTE_4KB = &((pte *) tmp)[PT_IDX];
        if (PTE_4KB->present) continue;

        pte Value{};
        Value.present = 1;
        Value.write = 1;
        Value.page_frame_number = PhysicalAddress >> 12;
        if (!ClaimEntry(PTE_4KB, Value)) continue;

        VA.offset = PhysicalAddress.offset;
        VA.p1_index = PT_IDX;
        VA.p2_index = PD_IDX;
        VA.p3_index = PDPT_IDX;
        VA.p4_index = PML4_IDX;

        Callback(VA);
        ReleaseEntry(PTE_4KB);
        return true;
    }

    return false;
}

// PhysicalMemory
template<typename T>
T AccessPhysicalMemory(address PhysicalAddress, pagesize PageSize)
{
    T tmp{};
    MapPhysicalToVirtual(PhysicalAddress,
        [&tmp](address VirtualAddress)
        {
            invlpg(VirtualAddress);
            memcpy(&tmp, VirtualAddress, sizeof(T));
        },
        PageSize
        );
    return tmp;
}

// Size must not cross the page the mapping covers; AccessVirtualMemory guarantees that
bool AccessPhysicalMemory(address PhysicalAddress, address pBuffer, size_t Size, pagesize PageSize, bool write = false)
{
    return MapPhysicalToVirtual(PhysicalAddress,
            [pBuffer, Size, write](address VirtualAddress)
            {
                invlpg(VirtualAddress);
                write ? memcpy(VirtualAddress, pBuffer, Size)
                      : memcpy(pBuffer, VirtualAddress, Size);
            },
            PageSize
    );
}

// Translate Virtual Address to Physical Address
std::pair<address, pagesize> GetPhysicalAddress(address VirtualAddress, cr3 CR3)
{
    // Translation...       Type 0: 4KB, Type 1: 2MB, Type 2: 1GB
    auto PML4E = AccessPhysicalMemory<pml4e>({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8}, Page_4KB);
    if (!PML4E.present) return {};

    auto PDPTE = AccessPhysicalMemory<pdpe>({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8}, Page_4KB);
    if (!PDPTE.present) return {};
    if (((pdpe_1gb)PDPTE).page_size)
        return {((pdpe_1gb)PDPTE).page_frame_number << 30 | VirtualAddress.offset_1gb(), Page_1GB};

    auto PDE = AccessPhysicalMemory<pde>({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8}, Page_4KB);
    if (!PDE.present) return {};
    if (((pde_2mb)PDE).page_size)
        return {((pde_2mb)PDE).page_frame_number << 21 | VirtualAddress.offset_2mb(), Page_2MB};

    auto PT = AccessPhysicalMemory<pte>({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8}, Page_4KB);
    if (!PT.present) return {};
    return {PT.page_frame_number << 12 | VirtualAddress.offset, Page_4KB};
}

// VirtualMemory
template<typename T>
T AccessVirtualMemory(address VirtualAddress, cr3 CR3)
{
    std::pair<address,pagesize> tmp = GetPhysicalAddress(VirtualAddress, CR3);
    if (!tmp.first) return T{};
    return AccessPhysicalMemory<T>(tmp.first, tmp.second);
}

bool AccessVirtualMemory(address VirtualAddress, cr3 CR3, address pBuffer, size_t Size, bool write = false)
{
    // Copy one page at a time: the next virtual page can map to an unrelated physical frame
    while (Size)
    {
        size_t Chunk = 0x1000 - VirtualAddress.offset;
        if (Chunk > Size) Chunk = Size;

        std::pair<address,pagesize> tmp = GetPhysicalAddress(VirtualAddress, CR3);
        if (!tmp.first) return false;
        if (!AccessPhysicalMemory(tmp.first, pBuffer, Chunk, tmp.second, write)) return false;

        VirtualAddress = address((uint64_t) VirtualAddress + Chunk);
        pBuffer = address((uint64_t) pBuffer + Chunk);
        Size -= Chunk;
    }
    return true;
}

// MmIsAddressValid
inline bool IsAddressValid(address VirtualAddress, cr3 CR3)
{
    return GetPhysicalAddress(VirtualAddress, CR3).first;
}
