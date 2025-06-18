using namespace arch;
using namespace intrin;

namespace
{
    pdpe_1gb* PDPTE_1GB;
    pde_2mb* PDE_2MB;
    pte* PTE_4KB;

    address VA{};
}

enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB,
    Page_Unmap
};

// MapPhysicalToVirtual
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize = Page_4KB)
{
    // Local variables
    int PML4_IDX, PDPT_IDX, PD_IDX, PT_IDX;
    cr3 CR3 = read_cr3();
    address tmp;

    pml4e* PML4E;
    pdpe* PDPTE;
    pde* PDE;

    // PML4
    tmp = win::MmGetVirtualForPhysical({CR3.pml4_frame_number << 12});
    for (PML4_IDX = 0; PML4_IDX < 512; ++PML4_IDX)
    {
        PML4E = &((pml4e *)tmp)[PML4_IDX];
        if (PML4E->present) break;
    }

    // PDPT
    tmp = win::MmGetVirtualForPhysical({PML4E->page_frame_number << 12});
    for (PDPT_IDX = 0; PDPT_IDX < 512; ++PDPT_IDX)
    {
        PDPTE = &((pdpe *) tmp)[PDPT_IDX];
        if (PageSize == Page_1GB)
        {
            if (PDPTE->present) continue;

            PDPTE_1GB = (pdpe_1gb*)PDPTE;
            PDPTE_1GB->present = 1;
            PDPTE_1GB->write = 1;
            PDPTE_1GB->page_size = 1;
            PDPTE_1GB->page_frame_number = PhysicalAddress >> 30;

            VA.offset = PhysicalAddress.offset;
            VA.p1_index = PhysicalAddress.p1_index;
            VA.p2_index = PhysicalAddress.p2_index;
            VA.p3_index = PDPT_IDX;
            VA.p4_index = PML4_IDX;

            Callback(VA);
            PDPTE_1GB->present = 0;
        }

        if (PDPTE->present) break;
    }

    // PD
    tmp = win::MmGetVirtualForPhysical({PDPTE->page_frame_number << 12});
    for (PD_IDX = 0; PD_IDX < 512; ++PD_IDX)
    {
        PDE = &((pde *) tmp)[PD_IDX];
        if (PageSize == Page_2MB)
        {
            if (PDE->present) continue;

            PDE_2MB = (pde_2mb *)PDE;
            PDE_2MB->present = 1;
            PDE_2MB->write = 1;
            PDE_2MB->page_size = 1;
            PDE_2MB->page_frame_number = PhysicalAddress >> 21;

            VA.offset = PhysicalAddress.offset;
            VA.p1_index = PhysicalAddress.p1_index;
            VA.p2_index = PD_IDX;
            VA.p3_index = PDPT_IDX;
            VA.p4_index = PML4_IDX;

            Callback(VA);
            PDE_2MB->present = 0;
            return true;
        }

        if (PDE->present) break;
    }

    // PT
    tmp = win::MmGetVirtualForPhysical({PDE->page_frame_number << 12});
    for (PT_IDX = 0; PT_IDX < 512; ++PT_IDX)
    {
        PTE_4KB = &((pte *) tmp)[PT_IDX];
        if (PTE_4KB->present) continue;

        PTE_4KB->present = 1;
        PTE_4KB->write = 1;
        PTE_4KB->page_frame_number = PhysicalAddress >> 12;

        VA.offset = PhysicalAddress.offset;
        VA.p1_index = PT_IDX;
        VA.p2_index = PD_IDX;
        VA.p3_index = PDPT_IDX;
        VA.p4_index = PML4_IDX;

        Callback(VA);
        PTE_4KB->present = 0;
        return true;
    }

    return false;
}

// Read Physical Memory
template<typename T>
T AccessPhysicalMemory(address PhysicalAddress, pagesize PageSize, bool write = false)
{
    T tmp{};
    MapPhysicalToVirtual(PhysicalAddress,
        [&tmp, write](address VirtualAddress)
        {
            invlpg(VirtualAddress);
            write ? memcpy(VirtualAddress, &tmp, sizeof(T))
                  : memcpy(&tmp, VirtualAddress, sizeof(T));
        },
        PageSize
        );
    return tmp;
}

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
    pdpe PML4E = AccessPhysicalMemory<pdpe>({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8}, Page_4KB);
    if (!PML4E) return {};

    auto PDPTE = AccessPhysicalMemory<pdpe>({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8}, Page_4KB);
    if (!PDPTE) return {};
    if (((pdpe_1gb)PDPTE).page_size)
        return {((pdpe_1gb)PDPTE).page_frame_number << 30 | VirtualAddress.offset_1gb(), Page_1GB};

    auto PDE = AccessPhysicalMemory<pde>({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8}, Page_4KB);
    if (!PDE) return {};
    if (((pde_2mb)PDE).page_size)
        return {((pde_2mb)PDE).page_frame_number << 21 | VirtualAddress.offset_2mb(), Page_2MB};

    auto PT = AccessPhysicalMemory<pte>({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8}, Page_4KB);
    if (!PT) return {};
    return {PT.page_frame_number << 12 | VirtualAddress.offset, Page_4KB};
}

// Read Virtual Memory
template<typename T>
T AccessVirtualMemory(address VirtualAddress, cr3 CR3, bool write = false)
{
    std::pair<address,pagesize> tmp = GetPhysicalAddress(VirtualAddress, CR3);
    if (!tmp.first) return T{};
    return AccessPhysicalMemory<T>(tmp.first, tmp.second, write);
}

bool AccessVirtualMemory(address VirtualAddress, cr3 CR3, address pBuffer, size_t Size, bool write = false)
{
    std::pair<address,pagesize> tmp = GetPhysicalAddress(VirtualAddress, CR3);
    if (!tmp.first) return false;
    return AccessPhysicalMemory(tmp.first, pBuffer, Size, tmp.second, write);
}